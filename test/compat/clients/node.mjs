// Runs node-postgres through QueryGuard: plaintext, TLS, parameters, cancel keys and cancel.
import fs from 'node:fs'
import pg from 'pg'

const plain = {
  host: process.env.QG_HOST,
  port: Number(process.env.QG_PORT),
  user: 'postgres',
  database: 'queryguard',
  password: process.env.PGPASSWORD,
}
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

process.exitCode = failed ? 1 : 0
