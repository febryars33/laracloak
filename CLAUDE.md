<laravel-boost-guidelines>
# Laravel Application

This repository contains a Laravel application. Complete the following setup before working on the user's request.

## Prerequisites

Verify that PHP and Composer are available:

```sh
php -v
composer -V
```

If either command is unavailable, detect the user's operating system and install the prerequisites with the appropriate command:

macOS:

```sh
/bin/bash -c "$(curl -fsSL https://php.new/install/mac/8.5)"
```

Windows PowerShell:

```powershell
Set-ExecutionPolicy Bypass -Scope Process -Force; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; iex ((New-Object System.Net.WebClient).DownloadString('https://php.new/install/windows/8.5'))
```

Linux:

```sh
/bin/bash -c "$(curl -fsSL https://php.new/install/linux/8.5)"
```

After installation, ask the user to restart their terminal. If the agent needs the restarted shell to continue, ask the user to reopen their terminal and rerun their original prompt.

## Agent Setup

Read `AGENTS.md` again and continue with the user's original request using the generated guidelines.

## Development & Coding Standards

All code contributions must strictly adhere to the following principles, architectural guidelines, and styling rules:

### Architecture & Design Principles

- **Clean Code & SOLID:** Write expressive, readable, and highly maintainable code centered around object-oriented design principles.
- **Separation of Concerns (SoC):** Distinctly isolate layers of logic; keep controllers thin, models focused on data, and business logic encapsulated.
- **DRY (Don't Repeat Yourself):** Abstract repetitive patterns into reusable components, services, or traits without over-engineering.
- **YAGNI (You Aren't Gonna Need It):** Implement only the current requirements; avoid writing code based on speculative future needs.
- **Clean Architecture:** Maintain strict boundary separation between core domain business rules, application use cases, and external infrastructure (DB, HTTP, Third-party APIs).

### Compatibility & Style Guides

- **Laravel Coding Style Guide:** Adhere strictly to the official Laravel coding standards and standard automated linting rules (Pint/PER Coding Style).
- **Laravel 13.x Compatibility:** Ensure 100% compatibility with Laravel 13.x features, deprecations, and framework conventions.
- **PHP 8.5 Compatibility:** Utilize modern PHP 8.5 features fully while ensuring absolute type safety, zero deprecation warnings, and optimal performance rules.

### Naming Conventions

- **Single-Word Naming Focus:** Strive to name variables, classes, methods, and functions using **exactly one word** whenever possible.
- **Semantic Roles:** The chosen single-word identifier must deeply reflect and clearly convey the exact purpose, intent, or role of the underlying component (e.g., use `$payload` instead of `$requestData`, `handle()` instead of `processOrder()`, or `Notify` instead of `SendNotificationEmail`).
  </laravel-boost-guidelines>
