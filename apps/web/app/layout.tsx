import type { ReactNode } from 'react';
export const metadata = { title: 'Chat Seguro - Starter', description: 'Proyecto académico' };
export default function Layout({ children }: { children: ReactNode }) {
  return <html lang="es"><body style={{fontFamily:'system-ui', margin: '3rem', maxWidth: 800}}>{children}</body></html>;
}
