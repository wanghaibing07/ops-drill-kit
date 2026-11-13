#!/usr/bin/env bash
set -Eeuo pipefail
[[ "$EUID" -eq 0 ]] || { echo 'Run via sudo' >&2; exit 1; }
[[ $# -eq 1 && $1 =~ ^[0-9]{5,6}$ ]] || { echo 'Invalid batch start' >&2; exit 2; }
start=$1
case "$start" in
    50001) sha=6250d5f820ec542c716c59049d814415edb819237ce3020d1968b4fe8d798018 ;;
    100001) sha=74864abbf242561f3949e57d643cafa400493422b4d688de305b62b7c6a2240a ;;
    150001) sha=f09bdd6a085133192b2544dd3a243f89a0bcbed35366dc2c40293d63fc3ae68c ;;
    200001) sha=4725e7a48ae1b82ea929c0f7712964c15d8c2b9cb2c9c91caf1bdb1e32c50d96 ;;
    250001) sha=ce4c368103906b78961c0abedafab60b9a17aa04f861783381137f86d48d7313 ;;
    300001) sha=d42f276b7a35384bf2d8520d274387a40ca61eab40cbba57deeffadd36f3eb6f ;;
    350001) sha=d27ae6c529685081cb15ef60866775c04cbfd3e3ea91d30818a7393ab8d288be ;;
    400001) sha=ebe30c7015053d39295a27af4464827f5ad576aa62b77e50cbcbcae11862a5e0 ;;
    450001) sha=0d17cf15dee8f55be059f040da0bbd523202e731f40ad5e3d159cd20168ac31b ;;
    *) echo 'Unapproved batch' >&2; exit 2 ;;
esac
# shellcheck source=/dev/null
source /opt/ops-drill-kit/lib/guard.sh
guard_require_lab
end=$((start + 49999))
table="orders_import_${start}_${end}"
root=/opt/ops-drill-kit
mysql_admin() { mysql --defaults-extra-file=/etc/opsdrill/mysql-admin.cnf "$@"; }
free_bytes=$(df -PB1 /var/lib/mysql | awk 'NR==2 {print $4}')
(( free_bytes >= 2147483648 )) || { echo 'Insufficient disk headroom' >&2; exit 1; }
state=$(mysql_admin -Nse "SELECT CONCAT((SELECT COUNT(*) FROM orderguard_stage3.orders),',',(SELECT COUNT(*) FROM orderguard.orders),',',@@GLOBAL.local_infile,',',(SELECT COUNT(*) FROM information_schema.tables WHERE table_schema='orderguard_stage3' AND table_name='${table}'))")
[[ "$state" == "$((start - 1)),5,0,0" ]] || { echo "Unexpected preflight state: $state" >&2; exit 1; }
file="/var/tmp/ops-drill-kit/orders-${start}-${end}.tsv"
[[ "$(sha256sum "$file" | awk '{print $1}')" == "$sha" ]] || { echo 'Batch hash mismatch' >&2; exit 1; }
echo "BEGIN batch ${start}-${end} sha256=${sha}"; date -u +'%Y-%m-%dT%H:%M:%SZ'
mysql_admin -e "CREATE TABLE orderguard_stage3.${table} LIKE orderguard_stage3.orders"
bash "$root/scripts/import_orders_segment.sh" "$start" "$sha"
bash "$root/scripts/promote_orders_segment.sh" "$start" "$sha"
bash "$root/scripts/promote_orders_segment.sh" "$start" "$sha" --apply
"$root/.venv/bin/python" "$root/scripts/verify_stage3_segment.py" "$end"
curl -fsS http://127.0.0.1:8080/ready >/dev/null
curl -fsS http://127.0.0.1:8080/orders/1001 | grep -Fq '"amount":"99.00"'
echo "PASS batch ${start}-${end}: legacy API healthy"; date -u +'%Y-%m-%dT%H:%M:%SZ'
