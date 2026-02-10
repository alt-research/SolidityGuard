import { Outlet } from 'react-router'
import Sidebar from './Sidebar'
import Header from './Header'
import StatusBar from './StatusBar'

export default function Layout() {
  return (
    <div className="min-h-screen flex bg-bg-primary">
      <Sidebar />
      <div className="flex-1 flex flex-col min-h-screen overflow-hidden">
        <Header />
        <main className="flex-1 overflow-y-auto">
          <Outlet />
        </main>
        <StatusBar />
      </div>
    </div>
  )
}
