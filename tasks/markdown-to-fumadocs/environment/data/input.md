# Getting Started

This guide explains how to set up the project.

## Installation

Run the following command:

```bash
npm install mypackage
```

## Usage

Create a configuration file:

```javascript
// config.js
export default {
  debug: true
};
```

Then use it in your app:

```typescript
// app.ts
import config from './config';
console.log(config.debug);
```

## Summary

That's all you need to get started.
