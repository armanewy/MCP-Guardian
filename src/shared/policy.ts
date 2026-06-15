import type { PolicyAction, PolicyEvaluation, PolicyRecord, RiskLevel, ToolInventoryItem } from './types';

const SENSITIVE_LEVELS = new Set<RiskLevel>(['high', 'critical']);

export function evaluatePolicy(input: {
  policies: PolicyRecord[];
  serverName: string;
  toolName: string;
  risk: RiskLevel;
}): PolicyEvaluation {
  const exact = input.policies.find(
    (policy) => policy.serverName === input.serverName && policy.toolName === input.toolName,
  );
  if (exact) {
    return {
      action: exact.action,
      source: 'exact',
      reason: `Matched ${input.serverName}/${input.toolName}`,
    };
  }

  const serverDefault = input.policies.find(
    (policy) => policy.serverName === input.serverName && policy.toolName === '*',
  );
  if (serverDefault) {
    return {
      action: serverDefault.action,
      source: 'server-default',
      reason: `Matched ${input.serverName}/*`,
    };
  }

  const globalDefault = input.policies.find(
    (policy) => policy.serverName === '*' && policy.toolName === '*',
  );
  if (globalDefault) {
    return {
      action: globalDefault.action,
      source: 'global-default',
      reason: 'Matched */*',
    };
  }

  return {
    action: SENSITIVE_LEVELS.has(input.risk) ? 'ask' : 'allow',
    source: 'risk-default',
    reason: SENSITIVE_LEVELS.has(input.risk)
      ? `${input.risk} risk tools require approval by default`
      : `${input.risk} risk tools are allowed by default`,
  };
}

export function shouldHideTool(policy: PolicyEvaluation): boolean {
  return policy.action === 'block';
}

export function filterVisibleTools(
  tools: ToolInventoryItem[],
  policies: PolicyRecord[],
): ToolInventoryItem[] {
  return tools.filter((tool) => {
    const policy = evaluatePolicy({
      policies,
      serverName: tool.serverName,
      toolName: tool.toolName,
      risk: tool.risk,
    });
    return !shouldHideTool(policy);
  });
}

export function coercePolicyAction(action: string): PolicyAction {
  if (action === 'allow' || action === 'ask' || action === 'block') {
    return action;
  }

  return 'ask';
}
