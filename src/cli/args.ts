export function parseArgs(argv: string[]): Map<string, string[]> {
  const parsed = new Map<string, string[]>();

  for (let index = 0; index < argv.length; index += 1) {
    const token = argv[index];
    if (!token.startsWith('--')) {
      continue;
    }

    const key = token.slice(2);
    const value = argv[index + 1]?.startsWith('--') || argv[index + 1] === undefined ? 'true' : argv[++index];
    const values = parsed.get(key) ?? [];
    values.push(value);
    parsed.set(key, values);
  }

  return parsed;
}

export function getArg(args: Map<string, string[]>, key: string, fallback = ''): string {
  return args.get(key)?.[0] ?? fallback;
}

export function getArgs(args: Map<string, string[]>, key: string): string[] {
  return args.get(key) ?? [];
}
