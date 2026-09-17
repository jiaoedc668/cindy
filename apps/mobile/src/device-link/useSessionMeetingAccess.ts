import { useCallback } from 'react';
import { useFocusEffect } from 'expo-router';
import { parseMeetingPeer } from '@cindy/device-link';
import { getMobileAuthOwner, isMobileAuthOwnerCurrent } from '@/auth/authOwnerGeneration';
import { useAuth } from '@/auth/AuthContext';
import { markDeviceAccessRevoked } from './accessRevoked';
import { useDeviceLink } from './DeviceLinkContext';
import { useSessionMeetingApi } from './useSessionMeetingApi';
import { revokedDevicesStore } from './revokedDevicesStore';
import { watchSessionMeetingAccess } from './sessionMeetingAccessWatch';

/** Only the foreground guest task reconciles membership; other peers are untouched. */
export function useSessionMeetingAccess(deviceId: string | undefined, sessionId: string, appActive: boolean) {
  const api = useSessionMeetingApi();
  const { accountGeneration } = useAuth();
  const { status, sessionMeetingAvailable, closeLink } = useDeviceLink();
  useFocusEffect(useCallback(() => {
    const peer = deviceId ? parseMeetingPeer(deviceId) : null;
    if (!appActive || status !== 'online' || sessionMeetingAvailable !== true
        || !deviceId || peer?.role !== 'host' || revokedDevicesStore.has(deviceId)) return;
    const owner = getMobileAuthOwner();
    return watchSessionMeetingAccess({
      meetingId: peer.meetingId, sessionId,
      read: () => api.get(peer.meetingId),
      isCurrent: () => isMobileAuthOwnerCurrent(owner),
      onRevoked: () => {
        markDeviceAccessRevoked(deviceId);
        closeLink(deviceId);
      },
    });
  }, [accountGeneration, api, appActive, closeLink, deviceId, sessionId, sessionMeetingAvailable, status]));
}
