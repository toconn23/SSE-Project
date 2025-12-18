# Framework-Aware Detection of Authorization Bypasses in Next.js APIs

## Installation

```bash
npm install
```

## Usage

Analyze a Next.js project:

```bash
npm run dev /path/to/your/nextjs/project
```

Then, run the index script in one of the following ways

```bash
#static analysis only
npx ts-node src/index.ts data/vuln-app

#static analysis + fuzzing
npx ts-node src/index.ts data/vuln-app --fuzz

#static analysis + fuzzing with custom URL
npx ts-node src/index.ts data/vuln-app --fuzz --base-url http://localhost:4000
```

### Optional: Security Configuration

Create a `security-config.json` file in your project root to customize the analyzer:

```json
{
  "customRoles": ["moderator", "superuser", "owner"],
  "sessionTokens": {
    "user": "valid-session-token-123",
    "admin": "admin-session-token-456"
  },
  "customSinks": [
    {
      "name": "payment_processing",
      "patterns": ["processPayment", "chargeCard", "refund"],
      "severity": "high",
      "description": "Payment processing operations"
    }
  ]
}
```

This helps the analyzer detect project-specific role checks and custom sinks in addition to standard keywords. Additionally, the sessionTokens are needed for fuzzing protected routes as a logged in user.
