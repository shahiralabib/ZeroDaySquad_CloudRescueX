import { useEffect, useMemo, useState, type ReactNode } from "react";
import { NavLink, useLocation, useNavigate } from "react-router-dom";
import { Activity, Bell, Boxes, ChevronDown, ChevronsLeft, ChevronsRight, CircleHelp, FlaskConical, History, LayoutDashboard, Menu, Search, Settings, ShieldAlert, ShieldCheck, Siren, X } from "lucide-react";
import { fetchHealth, fetchNotifications } from "../lib/api";

const navigation = [
  { label: "Overview", path: "/", icon: LayoutDashboard },
  { label: "Incidents", path: "/incidents", icon: ShieldAlert },
  { label: "Escalations", path: "/escalations", icon: Siren },
  { label: "Notifications", path: "/notifications", icon: Bell },
  { label: "Recovery History", path: "/recovery", icon: History },
  { label: "Services", path: "/services", icon: Boxes },
];

const administration = [
  { label: "Demo Control", path: "/demo", icon: FlaskConical },
  { label: "Settings", path: "/settings", icon: Settings },
];

export function Layout({ children }: { children: ReactNode }) {
  const [open, setOpen] = useState(false);
  const [collapsed, setCollapsed] = useState(false);
  const [notificationsOpen, setNotificationsOpen] = useState(false);
  const [unreadNotifications, setUnreadNotifications] = useState(0);
  const [apiStatus, setApiStatus] = useState<"checking" | "connected" | "unavailable">("checking");
  const location = useLocation();
  const navigate = useNavigate();
  const currentLabel = useMemo(() => [...navigation, ...administration].find((item) => item.path === location.pathname || (item.path !== "/" && location.pathname.startsWith(`${item.path}/`)))?.label ?? "Overview", [location.pathname]);

  useEffect(() => {
    let active = true;
    Promise.all([fetchHealth(), fetchNotifications()])
      .then(([, notifications]) => {
        if (active) setApiStatus("connected");
        if (active) setUnreadNotifications(notifications.filter((notification) => !notification.read).length);
      })
      .catch(() => {
        if (active) setApiStatus("unavailable");
      });
    return () => {
      active = false;
    };
  }, []);

  const goToIncidents = () => navigate("/incidents");

  return (
    <div className={`soc-shell ${collapsed ? "soc-shell-collapsed" : ""}`}>
      {open && <button className="soc-scrim" aria-label="Close navigation" onClick={() => setOpen(false)} />}
      <aside className={`soc-sidebar ${open ? "soc-sidebar-open" : ""}`} aria-label="Main navigation">
        <div className="soc-brand">
          <div className="soc-brand-mark"><ShieldCheck size={19} strokeWidth={2.2} /></div>
          <div className="soc-brand-copy"><span>CloudRescue<span className="text-cyan">X</span></span><small>SECURITY OPERATIONS</small></div>
          <button className="soc-icon-button soc-mobile-close" aria-label="Close navigation" onClick={() => setOpen(false)}><X size={17} /></button>
        </div>
        <div className="soc-workspace">
          <div className="soc-workspace-avatar"><Activity size={15} /></div>
          <div className="soc-workspace-copy"><span>CloudRescueX</span><small>Operations workspace</small></div>
          <ChevronDown size={15} className="text-slate-500" />
        </div>
        <div className="soc-nav-caption">WORKSPACE</div>
        <nav className="soc-nav">
          {navigation.map(({ label, path, icon: Icon }) => <NavLink key={path} to={path} onClick={() => setOpen(false)} title={collapsed ? label : undefined} className={({ isActive }) => `soc-nav-item ${isActive ? "soc-nav-item-active" : ""}`} end={path === "/"}><Icon size={17} strokeWidth={1.8} /><span className="soc-nav-label">{label}</span></NavLink>)}
        </nav>
        <div className="soc-nav-divider" />
        <div className="soc-nav-caption">ADMINISTRATION</div>
        <nav className="soc-nav">
          {administration.map(({ label, path, icon: Icon }) => <NavLink key={path} to={path} onClick={() => setOpen(false)} title={collapsed ? label : undefined} className={({ isActive }) => `soc-nav-item ${isActive ? "soc-nav-item-active" : ""}`}><Icon size={17} strokeWidth={1.8} /><span className="soc-nav-label">{label}</span>{label === "Demo Control" && <span className="soc-demo-tag">DEMO</span>}</NavLink>)}
        </nav>
        <div className="soc-sidebar-spacer" />
        <div className="soc-support-card"><CircleHelp size={16} /><div className="soc-nav-label"><strong>Need a hand?</strong><span>Review response guidance</span></div></div>
        <div className="soc-sidebar-footer">
          <div className="soc-tenant-status"><span className={`soc-status-dot ${apiStatus === "unavailable" ? "bg-red-400" : "bg-emerald-400"}`} />{apiStatus === "unavailable" ? "API requires attention" : "Systems monitored"}</div>
          <div className="soc-tenant-meta">CloudRescueX <span>v0 dashboard</span></div>
          <button className="soc-collapse-button" onClick={() => setCollapsed(!collapsed)} aria-label={collapsed ? "Expand sidebar" : "Collapse sidebar"}>{collapsed ? <ChevronsRight size={16} /> : <ChevronsLeft size={16} />}<span className="soc-nav-label">Collapse sidebar</span></button>
        </div>
      </aside>
      <section className="soc-main-column">
        <header className="soc-topbar">
          <div className="flex min-w-0 items-center gap-3"><button className="soc-icon-button soc-mobile-menu" aria-label="Open navigation" onClick={() => setOpen(true)}><Menu size={19} /></button><div className="soc-breadcrumb"><span>Workspace</span><span className="text-slate-600">/</span><strong>{currentLabel}</strong></div></div>
          <div className="soc-topbar-actions">
            <label className="soc-search"><Search size={15} /><input aria-label="Search incidents, services, or users" placeholder="Search anything..." onKeyDown={(event) => { if (event.key === "Enter") { goToIncidents(); event.currentTarget.blur(); } }} /><kbd>⌘ K</kbd></label>
            <div className="relative"><button className={`soc-icon-button ${notificationsOpen ? "soc-icon-button-selected" : ""}`} aria-label={`Notifications, ${unreadNotifications} unread`} onClick={() => setNotificationsOpen(!notificationsOpen)}><Bell size={18} />{unreadNotifications > 0 && <span className="soc-notification-dot" />}</button>{notificationsOpen && <div className="soc-notification-popover"><strong>Notifications</strong><span>{unreadNotifications} unread</span><button onClick={() => { navigate("/notifications"); setNotificationsOpen(false); }}>View all notifications</button></div>}</div>
            <div className="soc-topbar-separator" />
            <div className="soc-operator"><div className="soc-operator-avatar">OP</div><div className="soc-nav-label"><strong>Operator</strong><span><i />Authenticated</span></div></div>
          </div>
        </header>
        <main className="soc-content-area">{children}</main>
      </section>
    </div>
  );
}
