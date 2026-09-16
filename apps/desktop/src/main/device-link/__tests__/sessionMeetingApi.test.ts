import { beforeEach, describe, expect, it, vi } from 'vitest';

const state = vi.hoisted(() => ({ key: 'account:1', endpoint: 'https://relay.example.test', authenticated: true, boundary: false }));
const http = vi.hoisted(() => vi.fn());
vi.mock('../../appSessionState.js', () => ({ activeOwnerScopeKey: () => state.key, isAppSessionBoundaryPending: () => state.boundary }));
vi.mock('../../authManager.js', () => ({ getAuthState: () => ({ isAuthenticated: state.authenticated }) }));
vi.mock('../../clientEndpointsService.js', () => ({ getClientEndpoint: () => state.endpoint }));
vi.mock('../../serverApiClient.js', () => ({ serverApiFetch: http }));
import { sessionMeetingApi } from '../sessionMeetingApi.js';

beforeEach(() => {
  state.key = 'account:1'; state.endpoint = 'https://relay.example.test'; state.authenticated = true; state.boundary = false;
  http.mockReset();
});
describe('meeting Main HTTP adapter', () => {
  it('uses a redacted, bounded request through the existing auth client', async () => {
    http.mockImplementation(async (_path, options) => {
      expect(options.baseUrl()).toBe(state.endpoint);
      expect(options).toMatchObject({ timeoutMs: 15_000, cache: 'no-store', redactErrorDetails: true, logLabel: '/api/device-link/meetings' });
      return { meetingId: 'meeting', status: 'closed' };
    });
    await expect(sessionMeetingApi.close('meeting')).resolves.toMatchObject({ status: 'closed' });
  });
  it.each(['account', 'region', 'logout', 'boundary'])('blocks a retry after %s changes', async (change) => {
    http.mockImplementation(async (_path, options) => {
      expect(options.baseUrl()).toBe(state.endpoint);
      if (change === 'account') state.key = 'account:2';
      if (change === 'region') state.endpoint = 'https://other-relay.example.test';
      if (change === 'logout') state.authenticated = false;
      if (change === 'boundary') state.boundary = true;
      return { endpoint: options.baseUrl() };
    });
    await expect(sessionMeetingApi.close('meeting')).rejects.toThrow('account or region changed');
  });
  it('rejects late success when logout happens after sending', async () => {
    http.mockImplementation(async () => {
      state.authenticated = false;
      return { meetingId: 'meeting', status: 'closed' };
    });
    await expect(sessionMeetingApi.close('meeting')).rejects.toThrow('account or region changed');
  });
});
