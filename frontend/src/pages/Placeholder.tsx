import { EmptyState } from "../components/States";

export function Placeholder({ title, description }: { title: string; description: string }) {
  return <div className="space-y-6"><div><p className="text-sm font-medium text-cyan">OPERATIONS</p><h1 className="mt-2 text-2xl font-semibold">{title}</h1><p className="mt-2 text-sm text-slate-400">{description}</p></div><EmptyState message="No additional records are available in Phase 1. This view is ready for the next implementation phase." /></div>;
}

