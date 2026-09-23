import type { Register } from 'claude-code'

// The AD write tools. Each takes dry_run (default true), except the bulk tool, which takes
// apply (default false). Matches both spellings: `mcp__ad-ldap__…` for a server configured
// by hand, `mcp__plugin_ad-ldap_ad-ldap__…` for the one this plugin starts.
export const AD_WRITES =
  /^mcp__(?:plugin_[\w-]+_)?ad-ldap__ad_(set_user_attributes|set_user_manager|reset_password|set_account_status|unlock_account|set_computer_attributes|add_group_member|remove_group_member|bulk_assign_managers)$/

// Keys that are the call's mode or envelope, not what it does to the target.
const NOT_TARGET = new Set(['tool', 'tool_use_id', 'agentId', 'consent', 'dry_run', 'apply'])

type Args = Readonly<Record<string, unknown>>

/**
 * Registers the AD write guard: a commit (dry_run=false, or apply=true for the bulk tool) is
 * refused unless the identical call dry-ran successfully earlier this session. It never asks
 * anyone, so batches and `claude -p` runs go through once they dry-run first. It holds in any
 * permission mode and inside subagents, and the .catch refuses the call if the hook itself fails.
 */
export const register: Register = on => {
  // SHA-256s of AD calls that dry-ran successfully this session, keyed without dry_run/apply.
  const dryRuns = new Set<string>()

  on('session.end', ($, e, next) => {
    dryRuns.clear()
    return next(e)
  })

  on('tool.call', { tool: AD_WRITES }, async ($, e, next) => {
    const tool: string = e.tool
    const args: Args = e
    const isBulk = tool.endsWith('ad_bulk_assign_managers')
    const key = await keyOf(tool, args)

    if (!(isBulk ? args.apply === true : args.dry_run === false)) {
      const result = await next(e)
      if (!result.deny && !result.isError) dryRuns.add(key)
      return result
    }

    if (!dryRuns.has(key)) {
      return {
        deny:
          `ad-ldap guard: no matching dry run this session. Run the identical call with ` +
          `${isBulk ? 'apply=false' : 'dry_run=true'} first, check the diff, then commit.`,
      }
    }

    return next(e)
  }).catch(($, e, next) =>
    next.called
      ? next(e)
      : { deny: `ad-ldap guard failed (${next.error?.message ?? next.error?.kind ?? 'unknown'}), so the call was refused.` },
  )
}

/**
 * A SHA-256 of the tool and its target arguments, so a dry run and its commit match exactly
 * while a password never sits in memory as text.
 */
async function keyOf(tool: string, a: Args): Promise<string> {
  const target = Object.fromEntries(Object.entries(a).filter(([k]) => !NOT_TARGET.has(k)))
  const bytes = new TextEncoder().encode(tool + canonical(target))
  const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', bytes))
  return Array.from(digest, b => b.toString(16).padStart(2, '0')).join('')
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
