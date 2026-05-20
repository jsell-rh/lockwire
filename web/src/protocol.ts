export const SESSION_ID_ARGON_SALT = "lockwire-session-id-v1";
export const EPOCH_KEY_INFO_PREFIX = "lw-epoch-";
export const AUTH_KEY_INFO = "lw-auth-key";
export const SPAKE2_ASSOCIATED_DATA = "lockwire-v1";

export const KEY_LEN = 32;
export const SESSION_ID_LEN = 16;
export const NONCE_LEN = 12;
export const VIEWER_ID_LEN = 6;
export const GCM_TAG_LEN = 16;

export const SESSION_ID_ARGON_TIME = 1;
export const SESSION_ID_ARGON_MEMORY = 64 * 1024;
export const SESSION_ID_ARGON_THREADS = 1;

export const EPOCH_DURATION_SEC = 60;

export const MSG_TYPE_SPAKE2: number = 0x01;
export const MSG_TYPE_STREAM: number = 0x02;
export const MSG_TYPE_UNICAST: number = 0x03;
export const MSG_TYPE_HEARTBEAT: number = 0x04;
export const MSG_TYPE_PONG: number = 0x05;
export const MSG_TYPE_CONTROL: number = 0x06;
export const MSG_TYPE_TERM_SIZE: number = 0x07;

export const CTRL_REGISTRATION_ACK: number = 0x01;
export const CTRL_JOIN_ACK: number = 0x02;
export const CTRL_SESSION_NOT_FOUND: number = 0x03;
export const CTRL_SESSION_ENDED: number = 0x04;
export const CTRL_SESSION_FULL: number = 0x05;
export const CTRL_SESSION_ID_CONFLICT: number = 0x06;

export const HEARTBEAT_INTERVAL_MS = 5000;
export const VIEWER_REVOCATION_FAILURE_THRESHOLD = 10;
