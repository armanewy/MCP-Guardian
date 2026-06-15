import fs from 'node:fs';
import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { CallToolRequestSchema, ListToolsRequestSchema } from '@modelcontextprotocol/sdk/types.js';

const server = new Server(
  { name: 'mcp-guardian-fake-dangerous-server', version: '0.1.0' },
  { capabilities: { tools: {} } },
);

function appendCall(toolName: string): void {
  const logPath = process.env.FAKE_CALL_LOG;
  if (logPath) {
    fs.appendFileSync(logPath, `${toolName}\n`, 'utf8');
  }
}

server.setRequestHandler(ListToolsRequestSchema, async () => ({
  tools: [
    {
      name: 'read_file',
      description: 'Read private file content',
      inputSchema: { type: 'object', properties: { path: { type: 'string' } } },
    },
    {
      name: 'write_file',
      description: 'Write private file content',
      inputSchema: { type: 'object', properties: { path: { type: 'string' }, text: { type: 'string' } } },
    },
    {
      name: 'delete_file',
      description: 'Delete a file',
      inputSchema: { type: 'object', properties: { path: { type: 'string' } } },
      annotations: { destructiveHint: true },
    },
    {
      name: 'run_shell_command',
      description: 'Run a shell command',
      inputSchema: { type: 'object', properties: { command: { type: 'string' } } },
    },
    {
      name: 'send_message',
      description: 'Send a message',
      inputSchema: { type: 'object', properties: { channel: { type: 'string' }, text: { type: 'string' } } },
    },
    {
      name: 'echo_large_private_text',
      description: 'Echo a large private text payload',
      inputSchema: { type: 'object', properties: { text: { type: 'string' } } },
    },
    {
      name: 'leak_env',
      description: 'Return environment keys for testing',
      inputSchema: { type: 'object', properties: {} },
    },
  ],
}));

server.setRequestHandler(CallToolRequestSchema, async (request) => {
  appendCall(request.params.name);

  if (request.params.name === 'leak_env') {
    return {
      content: [{ type: 'text', text: JSON.stringify(process.env) }],
    };
  }

  if (request.params.name === 'echo_large_private_text') {
    return {
      content: [{ type: 'text', text: String(request.params.arguments?.text ?? '') }],
    };
  }

  return {
    content: [{ type: 'text', text: `${request.params.name}: ok` }],
  };
});

await server.connect(new StdioServerTransport());
