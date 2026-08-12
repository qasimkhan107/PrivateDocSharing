const FLOW = ['SENT', 'IN_REVIEW', 'DISCUSSION', 'SIGNED', 'COMPLETED'];

export function canTransition(current, next, actor, request) {
  if (current === next) return true;
  if (['REJECTED', 'CANCELLED', 'COMPLETED'].includes(current)) return false;

  if (next === 'REJECTED') return actor.userId === String(request.recipientId);
  if (next === 'CANCELLED') return actor.userId === String(request.senderId) || actor.role !== 'MEMBER';

  const currentIndex = FLOW.indexOf(current);
  const nextIndex = FLOW.indexOf(next);
  if (currentIndex === -1 || nextIndex !== currentIndex + 1) return false;

  if (next === 'SIGNED') return actor.userId === String(request.recipientId);
  if (next === 'COMPLETED') return actor.userId === String(request.senderId) || actor.role !== 'MEMBER';

  return actor.userId === String(request.recipientId) || actor.userId === String(request.senderId) || actor.role !== 'MEMBER';
}
