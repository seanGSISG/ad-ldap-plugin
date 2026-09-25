import type { EngineInterface, Register, ToolUseSummary } from 'claude-code'

// The AD write tools. Each takes dry_run (default true), except the bulk tool, which takes
// apply (default false). Matches both spellings: `mcp__ad-ldap__…` for a server configured
// by hand, `mcp__plugin_ad-ldap_ad-ldap__…` for the one this plugin starts.
export const AD_WRITES =
  /^mcp__(?:plugin_[\w-]+_)?ad-ldap__ad_(set_user_attributes|set_user_manager|reset_password|set_account_status|unlock_account|set_computer_attributes|add_group_member|remove_group_member|bulk_assign_managers)$/

// Keys that are the call's mode, not what it does to the target.
const NOT_TARGET = new Set(['consent', 'dry_run', 'apply'])

type Args = Readonly<Record<string, unknown>>

/**
 * Registers the AD write guard: a commit (dry_run=false, or apply=true for the bulk tool) is
 * refused unless the identical call dry-ran successfully earlier this session, as the session's
 * transcripts record it. It never asks anyone, so batches and `claude -p` runs go through once
 * they dry-run first. It holds in any permission mode and inside subagents, and the .catch
 * refuses the call if the hook itself fails.
 *
 * It decides on `tool.check`, never `tool.call`: while any plugin hooks `tool.call`, Claude Code
 * (2.1.282) runs tools outside an isolation:"worktree" subagent's cwd context, and every Bash
 * call in that subagent is refused.
 */
export const register: Register = on => {
  // Calls from a resumed transcript or from before a /clear: their dry runs don't count.
  const stale = new Set<string>()

  on('session.start', async ($, e, next) => {
    const started = await next(e)
    for (const use of await sessionUses($)) stale.add(use.tool_use_id)
    return started
  })

  on('session.end', async ($, e, next) => {
    for (const use of await sessionUses($)) stale.add(use.tool_use_id)
    return next(e)
  })

  on('tool.check', { tool: AD_WRITES }, async ($, e, next) => {
    const args = isArgs(e.input) ? e.input : {}
    const isBulk = e.tool.endsWith('ad_bulk_assign_managers')
    if (!isCommit(isBulk, args)) return next(e)

    const target = targetOf(args)
    for (const use of await sessionUses($)) {
      const dryRan = use.text !== undefined && !use.isError && !stale.has(use.tool_use_id)
      if (dryRan && use.tool === e.tool && !isCommit(isBulk, use.input) && targetOf(use.input) === target) return next(e)
    }
    return {
      decision: 'deny',
      reason:
        `ad-ldap guard: no matching dry run this session. Run the identical call with ` +
        `${isBulk ? 'apply=false' : 'dry_run=true'} first, check the diff, then commit.`,
    }
  }).catch(($, e, next) => ({
    decision: 'deny',
    reason: `ad-ldap guard failed (${next.error?.message ?? next.error?.kind ?? 'unknown'}), so the call was refused.`,
  }))
}

/**
 * Every answered-or-pending tool use in the session: the main loop's and each listed agent's.
 * With no agent list (a headless process tearing down), the main loop's alone: fewer dry runs
 * found only ever means more refusals.
 */
async function sessionUses($: EngineInterface): Promise<ToolUseSummary[]> {
  const uses: ToolUseSummary[] = []
  const agents = await $.agent.list().catch(() => [])
  for (const agentId of [undefined, ...agents.map(a => a.id)]) {
    const rows = await $.session.messages(agentId === undefined ? {} : { agentId })
    if (!('deny' in rows)) uses.push(...rows.flatMap(r => r.toolUses))
  }
  return uses
}

function isArgs(v: unknown): v is Args {
  return typeof v === 'object' && v !== null
}

function isCommit(isBulk: boolean, a: Args): boolean {
  return isBulk ? a.apply === true : a.dry_run === false
}

/** The call's target arguments as canonical JSON, so a dry run and its commit match exactly. */
function targetOf(a: Args): string {
  return canonical(Object.fromEntries(Object.entries(a).filter(([k]) => !NOT_TARGET.has(k))))
}

/** JSON with object keys sorted at every depth, so key order can't break a match. */
function canonical(v: unknown): string {
  if (Array.isArray(v)) return `[${v.map(canonical).join(',')}]`
  if (v && typeof v === 'object') {
    const entries = Object.entries(v).sort(([x], [y]) => (x < y ? -1 : 1))
    return `{${entries.map(([k, x]) => `${JSON.stringify(k)}:${canonical(x)}`).join(',')}}`
  }
  return JSON.stringify(v) ?? 'null'
}
