# Framework-Aware Detection of Authorization Bypasses in Next.js APIs

## Progress

### What is done

Currently, I have implemented the static analysis for routes and reporting. Currently, the analysis only goes at most 1 function outside of the route method, so if authorization checks or sinks are located 2 functions away, it will not detect. Additionally, the function must be within the same file. I aim to add support for custom function depth navigation and support for navigating through functions imported as described in the proposal.

### What needs to be done

The fuzzing needs to be implemented. Once the code is complete, I will evaluate my tool on public github repositories.

## Installation

```bash
npm install
npm run build
```

## Usage

Analyze a Next.js project:

```bash
npm run dev /path/to/your/nextjs/project
```

### Optional: Custom Role Configuration

Create a `security-config.json` file in your project root to specify custom authorization roles:

```json
{
  "customRoles": ["moderator", "superuser", "owner"]
}
```

This helps the analyzer detect project-specific role checks in addition to standard keywords like "admin" and "role"
