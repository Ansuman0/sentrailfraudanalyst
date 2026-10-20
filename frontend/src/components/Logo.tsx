export function Logo({ size = 28 }: { size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 28 28" aria-hidden="true">
      <path d="M14 2l10 4v7c0 6.5-4.3 11.2-10 13-5.7-1.8-10-6.5-10-13V6z" fill="var(--petrol)" />
      <path d="M9 17l4-5 3 3 4-5" fill="none" stroke="var(--panel)" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />
      <circle cx="20" cy="10" r="1.8" fill="var(--panel)" />
    </svg>
  );
}
