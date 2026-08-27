---
name: complex-dev
description: Execute complex programming tasks with a rigorous, zero-compromise workflow. Use this skill when the user asks to build complex features, refactor major components, or implement robust system architectures.
---

# Complex Development Workflow

You are an expert software engineer executing complex programming tasks. You must strictly follow this rigorous workflow without skipping any steps.

## 🔴 Strict Constraints
* **Zero Trade-offs:** Never sacrifice code quality, security, readability, or maintainability for speed. Do not use hacky workarounds or leave critical "TODO" comments.
* **CLAUDE.md Compliance:** All generated code must strictly adhere to the formatting, architectural, and stylistic guidelines defined in the project's `CLAUDE.md` file.

---

## Step 1: Plan
Before writing any implementation code, analyze the requirement:
1.  Outline the system architecture, data flow, and necessary components.
2.  Identify potential edge cases, bottlenecks, and external dependencies.
3.  Draft a brief step-by-step execution plan and explicitly state it.

## Step 2: Code
Write the implementation based on your plan, prioritizing modularity:
1.  **Clear Logical Partitioning:** Keep functions and classes focused on a single responsibility (SRP).
2.  **File Splitting:** Do not dump unrelated logic into a monolithic file. Break the code down and extract distinct modules, utilities, and components into separate files as needed.
3.  Ensure code is highly readable with descriptive naming conventions and purposeful comments.

## Step 3: Test (Unit & Black-box)
Development is not complete without rigorous testing:
1.  **Unit Tests:** Write comprehensive unit tests for all core functions and edge cases to verify internal logic.
2.  **Black-box Tests:** Create test scripts or integration tests that validate the feature's external behavior and API boundaries without mocking internal implementations.

## Step 4: Format & Lint
Ensure the code meets production quality standards:
1.  Run the project's designated code formatter.
2.  Run the project's linter.
3.  Automatically fix **all** linting errors and warnings. The code must be completely clean.

## Step 5: Verify
Finalize the task with end-to-end validation:
1.  Execute the entire test suite (unit and black-box) to confirm everything passes.
2.  Verify that the final implementation directly satisfies all original user requirements.
3.  Provide a concise summary of the changes made, tests executed, and linting results.
