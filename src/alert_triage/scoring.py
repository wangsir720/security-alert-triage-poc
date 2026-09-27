from __future__ import annotations

from .models import Alert, IntelMatch


SEVERITY_WEIGHT = {"low": 15, "medium": 30, "high": 45, "critical": 60}
CRITICALITY_WEIGHT = {"low": 5, "medium": 15, "high": 25, "critical": 35}
VERDICT_WEIGHT = {"benign": -25, "unknown": 0, "suspicious": 20, "malicious": 40}
TAG_WEIGHTS = {
    "phishing": 10,
    "ransomware": 15,
    "c2": 15,
    "scanning": 5,
    "bruteforce": 10,
    "credential-access": 10,
    "persistence": 10,
}


def score_alert(alert: Alert, matches: tuple[IntelMatch, ...]) -> int:
    score = SEVERITY_WEIGHT.get(alert.severity, 15)
    score += CRITICALITY_WEIGHT.get(alert.asset_criticality, 15)

    if matches:
        score += max(VERDICT_WEIGHT.get(match.verdict, 0) for match in matches)
        score += min(
            20,
            max((match.confidence - 50) // 5 for match in matches if match.confidence > 50),
        ) if any(match.confidence > 50 for match in matches) else 0
        for match in matches:
            score += sum(TAG_WEIGHTS.get(tag, 0) for tag in match.tags)
    else:
        score -= 5

    return max(0, min(100, score))


def risk_level(score: int) -> str:
    if score >= 70:
        return "high"
    if score >= 40:
        return "medium"
    return "low"


def build_recommendations(alert: Alert, matches: tuple[IntelMatch, ...]) -> tuple[str, ...]:
    recommendations: list[str] = []
    verdicts = {match.verdict for match in matches}
    tags = {tag for match in matches for tag in match.tags}

    if "malicious" in verdicts:
        recommendations.append("立即隔离相关主机或账号，并启动事件响应流程。")
        recommendations.append("保留原始告警、IOC 和主机证据，禁止直接覆盖或删除。")
    if "suspicious" in verdicts:
        recommendations.append("对相关 IOC 进行二次验证，并检查同源资产的关联告警。")
    if "phishing" in tags:
        recommendations.append("检查邮件网关、收件人点击记录和凭据重置情况。")
    if "ransomware" in tags:
        recommendations.append("优先确认备份完整性和横向移动迹象。")
    if "c2" in tags:
        recommendations.append("检查外联目标、DNS 请求和代理日志，确认是否存在失陷反连。")
    if not recommendations:
        recommendations.append("继续观察并补充资产上下文，暂不升级为安全事件。")
    return tuple(dict.fromkeys(recommendations))


def build_summary(alert: Alert, score: int, level: str, matches: tuple[IntelMatch, ...]) -> str:
    match_summary = "未命中本地威胁情报"
    if matches:
        match_summary = "命中 " + "、".join(
            f"{match.indicator}({match.verdict})" for match in matches
        )
    return (
        f"{alert.source} 产生“{alert.title}”告警，资产级别为 "
        f"{alert.asset_criticality}，风险评分 {score}，分级 {level}；{match_summary}。"
    )

