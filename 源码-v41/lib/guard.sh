#!/usr/bin/env bash

# ops-drill-kit 安全护栏
# 本文件只提供检查函数，不直接执行破坏性操作。

guard_die() {
    printf 'GUARD: %s\n' "$*" >&2
    return 1
}

# 检查是否具有 root 权限
guard_require_root() {
    [[ "$EUID" -eq 0 ]] || {
        guard_die "需要 root 权限"
        return 1
    }
}

# 检查当前是否为 VMware 虚拟机
guard_require_vm() {
    local virt

    command -v systemd-detect-virt >/dev/null 2>&1 || {
        guard_die "缺少 systemd-detect-virt"
        return 1
    }

    virt="$(systemd-detect-virt --vm 2>/dev/null)" || {
        guard_die "无法识别虚拟化环境"
        return 1
    }

    [[ "$virt" == "vmware" ]] || {
        guard_die "拒绝操作：当前环境不是 VMware"
        return 1
    }
}

# 检查项目初始化标记
guard_require_lab() {
    local marker

    [[ -f /etc/opsdrill-lab ]] || {
        guard_die "缺少项目环境标记"
        return 1
    }

    marker="$(< /etc/opsdrill-lab)"

    [[ "$marker" == "ops-drill-kit" ]] || {
        guard_die "项目环境标记不匹配"
        return 1
    }

    guard_require_vm || return 1
}

# 解析并限制磁盘实验路径
guard_resolve_lab_path() {
    local candidate="${1-}"
    local root resolved

    [[ -n "$candidate" ]] || {
        guard_die "目标路径不能为空"
        return 1
    }

    root="$(realpath -e -- /mnt/opsdrill)" || {
        guard_die "实验根目录不存在"
        return 1
    }

    resolved="$(realpath -m -- "$candidate")" || {
        guard_die "无法解析目标路径"
        return 1
    }

    case "$resolved" in
        "$root"/*)
            printf '%s\n' "$resolved"
            ;;
        *)
            guard_die "拒绝访问实验目录以外的路径"
            return 1
            ;;
    esac
}

# 只允许项目指定的网络 namespace
guard_require_namespace() {
    local ns="${1-}"

    case "$ns" in
        od-client|od-router|od-server) ;;
        *)
            guard_die "非法 network namespace"
            return 1
            ;;
    esac

    ip netns list | awk '{print $1}' | grep -Fxq -- "$ns" || {
        guard_die "指定 namespace 不存在"
        return 1
    }
}

# 检查指定 namespace 内的实验 nftables 表
guard_require_nft_table() {
    local ns="${1-}"

    guard_require_namespace "$ns" || return 1

    ip netns exec "$ns" nft list table inet od >/dev/null 2>&1 || {
        guard_die "实验 nftables 表不存在"
        return 1
    }
}
