/**
 * Claude Code hook integration (`agent-redact hook`).
 *
 * Reads the hook event JSON on stdin and exits with code 2 to block the action: for
 * UserPromptSubmit the prompt is rejected and the message is shown to the user; for
 * PreToolUse the tool call is refused and the message is shown to Claude. Messages name
 * secret *types*, never values.
 *
 * Fail-closed design, because the agent is the party being constrained:
 * - inline `agent-redact-ignore` comments are NOT honoured (an agent could add them);
 * - from the project config, which the agent can edit, only settings that ADD detection are
 *   used (custom patterns, entropy). allowlist/include/exclude are ignored unless the user
 *   passes `--config <path>` explicitly;
 * - large files are scanned in full (up to 64 MB; beyond that the read is refused), UTF-16
 *   files are decoded, and printable strings inside binary files are scanned.
 */
export interface HookInput {
    hook_event_name?: string;
    tool_name?: string;
    tool_input?: Record<string, unknown>;
    prompt?: string;
    cwd?: string;
}
export interface HookOptions {
    /** Also block Write/Edit/MultiEdit/NotebookEdit calls whose content contains secrets */
    blockWrites?: boolean;
    /** Explicit, user-controlled config file; applied in full (allowlist/exclude included) */
    configPath?: string;
}
export interface HookDecision {
    block: boolean;
    message?: string;
}
export declare function evaluateHook(input: HookInput, options?: HookOptions): HookDecision;
/** Entry point for `agent-redact hook [--block-writes] [--config <path>]`; returns the exit code */
export declare function runHook(args: string[]): Promise<number>;
