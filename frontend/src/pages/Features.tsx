import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ErrorBox, Loading, PageHeader } from "../components/common";
import { useAuth } from "../hooks/useAuth";
import { admin } from "../services/sentrail";
import { featureInfo } from "../utils/features";

export function Features() {
  const { refreshMe } = useAuth();
  const qc = useQueryClient();
  const q = useQuery({ queryKey: ["admin-features"], queryFn: admin.features });
  const toggle = useMutation({
    mutationFn: (a: { feature: string; enabled: boolean }) => admin.setFeature(a.feature, a.enabled),
    onSuccess: async () => {
      await qc.invalidateQueries({ queryKey: ["admin-features"] });
      await refreshMe(); // the menu follows the features
    },
  });

  return (
    <>
      <PageHeader title="Features" sub="Switch features on or off for your organization. Features outside your plan can't be turned on here; ask your Sentrail contact to change the plan." />
      {toggle.isError && <ErrorBox error={toggle.error} title="That change wasn't made" />}
      {q.isPending ? <Loading /> : q.isError ? <ErrorBox error={q.error} /> : (
        <div className="panel narrow">
          {q.data.map((f) => {
            const d = featureInfo(f.feature);
            return (
              <label key={f.feature} className="toggle">
                <input type="checkbox" checked={f.in_plan && f.enabled} disabled={!f.in_plan || toggle.isPending}
                       onChange={(e) => toggle.mutate({ feature: f.feature, enabled: e.target.checked })} />
                <span>
                  <b>{d.name}</b>{!f.in_plan && <span className="muted"> · not in your plan</span>}<br />
                  {d.text && <span className="muted">{d.text}</span>}
                </span>
              </label>
            );
          })}
        </div>
      )}
    </>
  );
}
