// The VAPID public key (not secret): browsers bind push subscriptions to it,
// and push services accept only wakeups signed by its private half, which
// lives in secrets/push.yaml and the Worker's VAPID_PRIVATE_KEY secret.
export const VAPID_PUBLIC_KEY =
  "BM0Dr7IETn6Mgt4ue9rSHzoDb_bIrxExMYdCAp7FUhmExP5Do8y7c5zb9PEGyLZY-TUfvoj2oquhsLFXG9DG_Ck";
