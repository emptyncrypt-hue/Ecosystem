import { handleRequest } from './handler.mjs';

// Keep test helpers in an imported module: workerd interprets every entrypoint
// export as a Worker handler, so this module must only export the handler.
export default {
  fetch(request, env) { return handleRequest(request, env); },
};
