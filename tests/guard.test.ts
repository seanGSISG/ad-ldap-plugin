import type { On } from 'claude-code'
import { describe, expect, test } from 'claude-code/testing'

import { AD_WRITES } from '../hooks/guard'

const RESET = 'mcp__ad-ldap__ad_reset_password'
const ADD = 'mcp__ad-ldap__ad_add_group_member'

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

  test('a commit with no dry run is refused', async ($, on) => {
    const ran = server(on)

    const r = await $.tool.call({ tool: ADD, group: 'VPN-Users', member: 'jdoe', dry_run: false })

    expect(r.deny).toContain('no matching dry run')
    expect(ran).toEqual([])
  })

  test('a commit after its identical dry run runs, argument order aside', async ($, on) => {
    const ran = server(on)

    await $.tool.call({ tool: RESET, identifier: 'jdoe', new_password: 'Hunter2!x', dry_run: true })
    const r = await $.tool.call({ new_password: 'Hunter2!x', identifier: 'jdoe', tool: RESET, dry_run: false })

    expect(r.deny).toBeUndefined()
    expect(ran).toEqual([RESET, RESET])
  })

  test('a failed dry run does not unlock the commit', async ($, on) => {
    on('tool.call', { tool: /ad-ldap__ad_/ }, () => ({ isError: true, result: 'no such user', text: 'no such user' }))

    await $.tool.call({ tool: ADD, group: 'VPN-Users', member: 'ghost' })
    const r = await $.tool.call({ tool: ADD, group: 'VPN-Users', member: 'ghost', dry_run: false })

    expect(r.deny).toContain('no matching dry run')
  })

  test('a dry run for one target does not unlock a commit for another', async ($, on) => {
    server(on)

    await $.tool.call({ tool: ADD, group: 'VPN-Users', member: 'jdoe' })
    const r = await $.tool.call({ tool: ADD, group: 'VPN-Users', member: 'asmith', dry_run: false })

    expect(r.deny).toContain('no matching dry run')
  })

  test('the bulk tool commits on apply=true only after an apply=false plan', async ($, on) => {
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
