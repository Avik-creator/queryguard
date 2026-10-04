// Runs node-postgres through QueryGuard: plaintext, TLS, parameters, cancel keys, cancel and rule rejections.
import fs from 'node:fs'
import pg from 'pg'

const plain = {
  host: process.env.QG_HOST,
  port: Number(process.env.QG_PORT),
  user: 'postgres',
  database: 'queryguard',
  password: process.env.PGPASSWORD,
}
// QG_RULES_PORT blocks UPDATE and DELETE without WHERE.
const rules = { ...plain, port: Number(process.env.QG_RULES_PORT) }
const tls = { ...plain, host: 'localhost', ssl: { ca: fs.readFileSync(process.env.QG_CA), servername: 'localhost' } }

let failed = false

async function check(name, fn) {
  try {
    await fn()
    console.log(`ok   ${name}`)
  } catch (err) {
    console.log(`FAIL ${name}: ${err.message}`)
    failed = true
  }
}

async function withClient(config, fn) {
  const client = new pg.Client(config)
  await client.connect()
  try {
    return await fn(client)
  } finally {
    await client.end()
  }
}

function expect(cond, msg) {
  if (!cond) throw new Error(msg)
}

console.log(`node ${process.version}, pg ${JSON.parse(fs.readFileSync('node_modules/pg/package.json')).version}`)

await check('plaintext', () =>
  withClient(plain, async (c) => {
    const { rows } = await c.query('select 1 as one')
    expect(rows[0].one === 1, `select 1 returned ${rows[0].one}`)
  }))

await check('TLS', () =>
  withClient(tls, async (c) => {
    expect(c.connection.stream.encrypted === true, 'connection is not encrypted')
    await c.query('select 1')
  }))

await check('parameters', () =>
  withClient(plain, async (c) => {
    const { rows } = await c.query('select $1::int + $2::int as sum', [2, 3])
    expect(rows[0].sum === 5, `2 + 3 returned ${rows[0].sum}`)
  }))

await check('proxy-issued cancel key', () =>
  withClient(plain, async (c) => {
    const { rows } = await c.query('select pg_backend_pid() as pid')
    expect(c.processID !== rows[0].pid, `client was given the real backend pid ${rows[0].pid}`)
  }))

await check('cancel', () =>
  withClient(plain, async (c) => {
    const sleep = c.query('select pg_sleep(30)')
    // node-postgres cancels through a second Client, which sends the first one's key data.
    setTimeout(() => new pg.Client(plain).cancel(c, c.activeQuery), 300)
    const err = await sleep.then(() => null, (e) => e)
    expect(err?.code === '57014', `pg_sleep(30) ended with ${err?.code ?? 'no error'}`)
  }))

// The tables don't exist, so a missed rejection fails with 42P01 instead.
await check('rejected statement', () =>
  withClient(rules, async (c) => {
    // Without parameters node-postgres sends a simple Query; with them, Parse/Bind/Execute.
    for (const [text, values] of [['delete from qg_no_such_table', []], ['update qg_no_such_table set n = $1', [1]]]) {
      const err = await c.query(text, values).then(() => null, (e) => e)
      expect(err?.code === '42501', `${text} ended with ${err?.code ?? 'no error'}`)
      const { rows } = await c.query('select 1 as one')
      expect(rows[0].one === 1, 'connection unusable after the rejection')
    }
  }))

await check('rejection fails the transaction', () =>
  withClient(rules, async (c) => {
    await c.query('begin')
    const rejected = await c.query('delete from qg_no_such_table').then(() => null, (e) => e)
    expect(rejected?.code === '42501', `delete ended with ${rejected?.code ?? 'no error'}`)
    const next = await c.query('select 1').then(() => null, (e) => e)
    expect(next?.code === '25P02', `next statement ended with ${next?.code ?? 'no error'}`)
    await c.query('rollback')
    await c.query('select 1')
  }))

process.exitCode = failed ? 1 : 0
