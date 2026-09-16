import { createSessionMeetingApi, SessionMeetingScopeChangedError } from '@cindy/device-link';
import { activeOwnerScopeKey, isAppSessionBoundaryPending } from '../appSessionState.js';
import { getAuthState } from '../authManager.js';
import { getClientEndpoint } from '../clientEndpointsService.js';
import { serverApiFetch } from '../serverApiClient.js';

/** Main-owned adapter. Tokens remain inside the existing authenticated HTTP client. */
export const sessionMeetingApi = createSessionMeetingApi({
  captureScope() {
    const key = activeOwnerScopeKey();
    const endpoint = getClientEndpoint('deviceLinkApiBaseUrl');
    return { isCurrent: () => getAuthState().isAuthenticated && !isAppSessionBoundaryPending() &&
      activeOwnerScopeKey() === key && getClientEndpoint('deviceLinkApiBaseUrl') === endpoint };
  },
  request(path, options) {
    return serverApiFetch<unknown>(path, {
      method: options.method,
      body: options.body,
      // Executed before EACH physical attempt, including automatic token refresh.
      // A new account/region cannot submit an old invitation or moderation action.
      baseUrl: () => {
        if (!options.isCurrent()) throw new SessionMeetingScopeChangedError();
        return getClientEndpoint('deviceLinkApiBaseUrl');
      },
      timeoutMs: 15_000,
      cache: 'no-store',
      logLabel: '/api/device-link/meetings',
      redactErrorDetails: true,
      allowedRedactedErrorCodes: ['NOT_FOUND', 'CONFLICT', 'PERMISSION_DENIED', 'INVALID_PARAMS', 'RATE_LIMITED'],
    });
  },
});
