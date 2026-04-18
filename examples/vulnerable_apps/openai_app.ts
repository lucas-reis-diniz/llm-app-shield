// examples/vulnerable_apps/openai_app.ts
/**
 * ⚠️  INTENTIONALLY VULNERABLE NODE.JS APP — FOR DEMONSTRATION PURPOSES ONLY ⚠️
 *
 * Vulnerabilities:
 * 1. [LLM01-003]   Prompt injection via template literal
 * 2. [LLM02-XSS]   LLM output set as innerHTML (XSS)
 * 3. [LLM02-EVAL]  LLM output passed to eval()
 * 4. [LLM06-EMAIL] Email/PII sent to external LLM
 * 5. [SEC-OPENAI]  Hardcoded API key
 */

import OpenAI from "openai";

// ❌ Hardcoded OpenAI API key (SEC-OPENAI - CRITICAL)
const openai = new OpenAI({
  apiKey: "sk-proj-abc123realopenapikey987654321exposed",
});

interface User {
  name: string;
  email: string;
  cpf: string;
}

// ❌ VULNERABILITY 1: Prompt injection via template literal (LLM01 - CRITICAL)
async function chatWithUser(userInput: string, user: User): Promise<string> {
  const response = await openai.chat.completions.create({
    model: "gpt-4",
    messages: [
      {
        role: "system",
        content: `You are an assistant for ${user.name} (${user.email}, CPF: ${user.cpf}).`,
        // ❌ PII embedded in system prompt + user.name could be injection vector
      },
      {
        role: "user",
        content: `${userInput}`, // ❌ Direct template literal interpolation
      },
    ],
  });

  return response.choices[0].message.content || "";
}

// ❌ VULNERABILITY 2: LLM output as innerHTML (XSS - CRITICAL)
async function renderAIResponse(userMessage: string): Promise<void> {
  const response = await openai.chat.completions.create({
    model: "gpt-4",
    messages: [{ role: "user", content: `Format as HTML: ${userMessage}` }],
  });

  const aiResponse = response.choices[0].message.content || "";

  // ❌ Setting innerHTML with LLM output — XSS attack vector!
  document.getElementById("output")!.innerHTML = aiResponse;
}

// ❌ VULNERABILITY 3: LLM output in eval() (Code Execution - CRITICAL)
async function executeAISuggestion(task: string): Promise<void> {
  const response = await openai.chat.completions.create({
    model: "gpt-4",
    messages: [
      { role: "user", content: `Write JavaScript code to: ${task}` },
    ],
  });

  const generatedCode = response.choices[0].message.content || "";

  // ❌ Executing LLM-generated code — Remote Code Execution!
  eval(generatedCode); // NEVER DO THIS
}

// ❌ VULNERABILITY 4: SQL injection via LLM output
async function queryWithLLM(userInput: string, db: any): Promise<any> {
  const response = await openai.chat.completions.create({
    model: "gpt-4",
    messages: [{ role: "user", content: `Generate SQL query for: ${userInput}` }],
  });

  const generatedSQL = response.choices[0].message.content || "";

  // ❌ Executing LLM-generated SQL directly!
  return db.query(generatedSQL); // SQL injection via LLM output!
}

// OpenAI function definition with dangerous capabilities
const dangerousFunctionDefs = [
  {
    type: "function",
    function: {
      name: "execute_code", // ❌ LLM08: Agent can execute arbitrary code
      description: "Execute JavaScript code",
      parameters: {
        type: "object",
        properties: {
          code: { type: "string", description: "Code to execute" },
        },
      },
    },
  },
  {
    type: "function",
    function: {
      name: "execute_sql", // ❌ LLM08: Agent can run SQL
      description: "Execute SQL query on production database",
      parameters: {
        type: "object",
        properties: {
          query: { type: "string" },
        },
      },
    },
  },
];

export { chatWithUser, renderAIResponse, executeAISuggestion };
