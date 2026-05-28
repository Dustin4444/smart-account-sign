import { RealtimeCursors } from '@/components/realtime-cursors'

export default function Page() {
  return (
    <main className="flex min-h-svh items-center justify-center">
      <RealtimeCursors roomName="default" username="user" />
    </main>
  )
}
