import type { On } from 'claude-code'
import { describe, expect, test } from 'claude-code/testing'

import { AD_WRITES, CANCEL, RUN } from '../hooks/guard'

const RESET = 'mcp__ad-ldap__ad_reset_password'
const ADD = 'mcp__ad-ldap__ad_add_group_member'

/** Answers the confirmation dialog beneath the guard with `label`, recording each question. */
function answering(on: On, label: string | null) {
  const asked: string[] = []
  // A regex: AskUserQuestion is deferred, so it isn't in the typed tool names.
  on('tool.call', { tool: /^AskUserQuestion$/ }, ($, e) => {
    const args: Readonly<Record<string, unknown>> = e
    const questions = Array.isArray(args.questions) ? args.questions : []
    const question = String(questions[0]?.question ?? '')
    asked.push(question)
    return label === null ? { deny: 'dismissed' } : { result: { questions, answers: { [question]: label } } }
  })
  return asked
}

/** Serves every ad-ldap tool beneath the guard and records the calls that reached it. */
function server(on: On) {
  const ran: string[] = []
  on('tool.call', { tool: /ad-ldap__ad_/ }, ($, e) => {
    ran.push(e.tool)
    return { result: [{ type: 'text', text: '{"ok":true}' }] }
  })
  return ran
}

describe('guard', () => {
  test('matches the plugin-started server and a hand-configured one, writes only', () => {
    expect(AD_WRITES.test('mcp__plugin_ad-ldap_ad-ldap__ad_add_group_member')).toBe(true)
    expect(AD_WRITES.test('mcp__ad-ldap__ad_add_group_member')).toBe(true)
    expect(AD_WRITES.test('mcp__plugin_ad-ldap_ad-ldap__ad_get_user')).toBe(false)
  })

  test('a commit with no dry run is refused without asking', async ($, on) => {
    const asked = answering(on, RUN)
    const ran = server(on)

    const r = await $.tool.call({ tool: ADD, group: 'VPN-Users', member: 'jdoe', dry_run: false })

    expect(r.deny).toContain('no matching dry run')
    expect(asked).toEqual([])
    expect(ran).toEqual([])
  })

  test('a commit after its dry run asks, masks the password, then runs', async ($, on) => {
    const asked = answering(on, RUN)
    const ran = server(on)

    await $.tool.call({ tool: RESET, identifier: 'jdoe', new_password: 'Hunter2!x', dry_run: true })
    const r = await $.tool.call({ new_password: 'Hunter2!x', identifier: 'jdoe', tool: RESET, dry_run: false })

    expect(r.deny).toBeUndefined()
    expect(ran).toEqual([RESET, RESET])
    expect(asked[0]).toContain('new_password=••••')
    expect(asked[0]).not.toContain('Hunter2')
  })

  test('a declined commit never reaches the server', async ($, on) => {
    answering(on, CANCEL)
    const ran = server(on)

    await $.tool.call({ tool: ADD, group: 'VPN-Users', member: 'jdoe' })
    const r = await $.tool.call({ tool: ADD, group: 'VPN-Users', member: 'jdoe', dry_run: false })

    expect(r.deny).toContain('declined')
    expect(ran).toEqual([ADD])
  })

  test('a dismissed dialog refuses the commit', async ($, on) => {
    answering(on, null)
    server(on)

    await $.tool.call({ tool: ADD, group: 'VPN-Users', member: 'jdoe' })
    const r = await $.tool.call({ tool: ADD, group: 'VPN-Users', member: 'jdoe', dry_run: false })

    expect(r.deny).toContain('no one confirmed')
  })

  test('a dry run for one target does not unlock a commit for another', async ($, on) => {
    answering(on, RUN)
    server(on)

    await $.tool.call({ tool: ADD, group: 'VPN-Users', member: 'jdoe' })
    const r = await $.tool.call({ tool: ADD, group: 'VPN-Users', member: 'asmith', dry_run: false })

    expect(r.deny).toContain('no matching dry run')
  })

  test('the bulk tool commits on apply=true only after an apply=false plan', async ($, on) => {
    answering(on, RUN)
    const ran = server(on)
    const bulk = 'mcp__ad-ldap__ad_bulk_assign_managers'

    const early = await $.tool.call({ tool: bulk, apply: true })
    await $.tool.call({ tool: bulk })
    const r = await $.tool.call({ tool: bulk, apply: true })

    expect(early.deny).toContain('apply=false')
    expect(r.deny).toBeUndefined()
    expect(ran).toEqual([bulk, bulk])
  })
})
