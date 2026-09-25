import type { On, SessionMessage } from 'claude-code'
import { describe, expect, test } from 'claude-code/testing'
import type { Engine } from 'claude-code/testing'

import { AD_WRITES } from '../hooks/guard'

const RESET = 'mcp__ad-ldap__ad_reset_password'
const ADD = 'mcp__ad-ldap__ad_add_group_member'
const BULK = 'mcp__ad-ldap__ad_bulk_assign_managers'

type Args = Record<string, unknown>
type Transcripts = Map<string, SessionMessage[]>

/**
 * Answers what the guard reads beneath it: each loop's transcript ('main' plus any agent ids),
 * the session's start and end, and the engine's own verdict, `allow`, as in bypassPermissions.
 */
function session(on: On): Transcripts {
  const transcripts: Transcripts = new Map([['main', []]])
  on('agent.list', () => ({
    value: [...transcripts.keys()].filter(k => k !== 'main').map(id => ({ id, description: id, type: 'general-purpose', status: 'completed' })),
  }))
  on('session.messages', ($, e) => ({ value: transcripts.get(e.agentId ?? 'main') ?? [] }))
  on('session.start', ($, e) => ({ cwd: e.cwd }))
  on('session.end', ($, e) => ({ sessionId: e.sessionId }))
  on('tool.check', () => ({ decision: 'allow' }))
  return transcripts
}

/** Records a call in `loop`'s transcript: answered with `text`, failed, or still in flight. */
function ran(t: Transcripts, tool: string, input: Args, outcome: 'ok' | 'error' | 'pending' = 'ok', loop = 'main') {
  const rows = t.get(loop) ?? []
  const answer = outcome === 'pending' ? {} : outcome === 'error' ? { text: 'no such user', isError: true as const } : { text: '{"ok":true}' }
  const use = { tool_use_id: `toolu_${loop}_${rows.length}`, tool, input, ...answer }
  t.set(loop, [...rows, { role: 'assistant', text: '', toolUses: [use] }])
}

/** The model's commit reaching the permission decision. */
const commit = ($: Engine, tool: string, input: Args) => $.tool.check({ tool, input, tool_use_id: 'toolu_commit' })

describe('guard', () => {
  test('matches the plugin-started server and a hand-configured one, writes only', () => {
    expect(AD_WRITES.test('mcp__plugin_ad-ldap_ad-ldap__ad_add_group_member')).toBe(true)
    expect(AD_WRITES.test('mcp__ad-ldap__ad_add_group_member')).toBe(true)
    expect(AD_WRITES.test('mcp__plugin_ad-ldap_ad-ldap__ad_get_user')).toBe(false)
  })

  test('a commit with no dry run is refused; a dry run itself goes through', async ($, on) => {
    session(on)

    const r = await commit($, ADD, { group: 'VPN-Users', member: 'jdoe', dry_run: false })
    const dry = await commit($, ADD, { group: 'VPN-Users', member: 'jdoe' })

    expect(r.decision).toBe('deny')
    expect(r.reason).toContain('no matching dry run')
    expect(dry.decision).toBe('allow')
  })

  test('a commit after its identical dry run runs, argument order aside', async ($, on) => {
    const t = session(on)
    ran(t, RESET, { identifier: 'jdoe', new_password: 'Hunter2!x', dry_run: true })

    const r = await commit($, RESET, { new_password: 'Hunter2!x', identifier: 'jdoe', dry_run: false })

    expect(r.decision).toBe('allow')
  })

  test('a failed, still-running or refused-commit call does not unlock the commit', async ($, on) => {
    const t = session(on)
    ran(t, ADD, { group: 'VPN-Users', member: 'ghost' }, 'error')
    ran(t, ADD, { group: 'VPN-Users', member: 'ghost' }, 'pending')
    ran(t, ADD, { group: 'VPN-Users', member: 'ghost', dry_run: false })

    const r = await commit($, ADD, { group: 'VPN-Users', member: 'ghost', dry_run: false })

    expect(r.decision).toBe('deny')
  })

  test('a dry run for one target, or on another tool, does not unlock a commit', async ($, on) => {
    const t = session(on)
    ran(t, ADD, { group: 'VPN-Users', member: 'jdoe' })
    ran(t, 'mcp__ad-ldap__ad_remove_group_member', { group: 'VPN-Users', member: 'asmith' })

    const r = await commit($, ADD, { group: 'VPN-Users', member: 'asmith', dry_run: false })

    expect(r.decision).toBe('deny')
  })

  test("a subagent's dry run counts session-wide", async ($, on) => {
    const t = session(on)
    ran(t, ADD, { group: 'VPN-Users', member: 'jdoe' }, 'ok', 'agent_1')

    const r = await commit($, ADD, { group: 'VPN-Users', member: 'jdoe', dry_run: false })

    expect(r.decision).toBe('allow')
  })

  test('the bulk tool commits on apply=true only after an apply=false plan', async ($, on) => {
    const t = session(on)

    const early = await commit($, BULK, { apply: true })
    ran(t, BULK, {})
    const r = await commit($, BULK, { apply: true })

    expect(early.reason).toContain('apply=false')
    expect(r.decision).toBe('allow')
  })

  test('a dry run from a resumed transcript, or from before a /clear, does not count', async ($, on) => {
    const t = session(on)
    ran(t, ADD, { group: 'VPN-Users', member: 'jdoe' })
    await $.session.start({ cwd: '/repo', surface: 'terminal', isInteractive: true })
    ran(t, ADD, { group: 'VPN-Users', member: 'asmith' })
    await $.session.end({ reason: 'clear', sessionId: 's1', resume: { id: 's1' } })

    const resumed = await commit($, ADD, { group: 'VPN-Users', member: 'jdoe', dry_run: false })
    const cleared = await commit($, ADD, { group: 'VPN-Users', member: 'asmith', dry_run: false })

    expect(resumed.decision).toBe('deny')
    expect(cleared.decision).toBe('deny')
  })

  test('the call is refused when the guard itself fails', async ($, on) => {
    on('agent.list', () => {
      throw new Error('boom')
    })
    on('tool.check', () => ({ decision: 'allow' }))

    const r = await commit($, ADD, { group: 'VPN-Users', member: 'jdoe', dry_run: false })

    expect(r.decision).toBe('deny')
    expect(r.reason).toContain('ad-ldap guard failed')
  })
})
