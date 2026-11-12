package app

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"mihomo-policy/internal/analyze"
	"mihomo-policy/internal/collect"
)

func CollectOnly(ctx context.Context, c *collect.Collector) error {
	owner := collect.ID()
	name := "collector:" + c.Source
	ok, err := c.DB.Lease(ctx, name, owner, time.Now(), 30*time.Second)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("another collector already owns source %s", c.Source)
	}
	defer func() {
		releaseCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = c.DB.ReleaseLease(releaseCtx, name, owner)
	}()
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	leaseErr := make(chan error, 1)
	var wg sync.WaitGroup
	wg.Add(3)
	go func() { defer wg.Done(); _ = c.Poll(ctx) }()
	go func() { defer wg.Done(); _ = c.Logs(ctx) }()
	go func() {
		defer wg.Done()
		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				ok, e := c.DB.Lease(ctx, name, owner, time.Now(), 30*time.Second)
				if e != nil || !ok {
					if e == nil {
						e = fmt.Errorf("collector lease lost")
					}
					leaseErr <- e
					cancel()
					return
				}
			}
		}
	}()
	<-ctx.Done()
	cancel()
	wg.Wait()
	select {
	case err := <-leaseErr:
		return err
	default:
		return nil
	}
}
func Markdown(r analyze.Report) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# Mihomo 规则分析\n\n数据源：%s  \n规则版本：`%s`  \n生成时间：%s\n\n", escape(r.Source), r.PolicyVersion, r.GeneratedAt.Format("2006-01-02T15:04:05Z"))
	fmt.Fprintf(&b, "访问统计开始：%s  \n独立探测证据开始：%s\n\n", r.Since.Format(time.RFC3339), r.EvidenceSince.Format(time.RFC3339))
	fmt.Fprintf(&b, "证据门槛：%d 组、%d 个 %.1fh 窗口、跨度 %.1fh；最近证据不超过 %.1fh，复核最近 %d 组。\n\n", r.Requirements.MinPairs, r.Requirements.MinWindows, r.Requirements.WindowHours, r.Requirements.MinSpanHours, r.Requirements.MaxAgeHours, r.Requirements.RecentPairs)
	b.WriteString("| 域名 | 本地草案分类 / 策略组 | 已观测流量 | 失败事件 | 线路评估 | 变更判断 | 优先级复核 |\n|---|---|---:|---:|---|---|---|\n")
	for _, c := range r.Candidates {
		fmt.Fprintf(&b, "| %s | %s / %s | %d B | %d | %s | %s | %t |\n", escape(c.Traffic.Host), escape(c.Match.Category), escape(c.Match.Policy), c.Traffic.Up+c.Traffic.Down, c.Traffic.Failures, c.RouteVerdict, c.Suggestion, c.PriorityReview)
	}
	for _, c := range r.Candidates {
		fmt.Fprintf(&b, "\n## %s\n\n%s\n", escape(c.Traffic.Host), c.Reason)
		fmt.Fprintf(&b, "\n数据来源：%s；已观测出口类型：%s。\n", c.Origin, c.CurrentRoute)
		if c.Change != nil {
			destination := c.Change.Policy
			if destination == "" {
				destination = "代理策略组待指定"
			}
			fmt.Fprintf(&b, "\n待复核：%s → %s；%s,%s。%s\n", escape(c.Match.Policy), escape(destination), c.Change.Type, escape(c.Change.Value), c.Change.Note)
		}
		for _, route := range c.Traffic.Routes {
			fmt.Fprintf(&b, "\n- 实际线路 %s；节点 %s；规则 %s；%d B；最后观测 %s。\n", escape(route.Route), escape(route.Node), escape(route.Rule), route.Up+route.Down, route.LastSeen.Format(time.RFC3339))
		}
		for _, e := range c.Evidence {
			fmt.Fprintf(&b, "\n- %s：%d 组配对，%d 个时间窗口，跨度 %.1f 小时；DIRECT %d/%d / PROXY %d/%d；成功样本 P50 %s / %s；P95 %s / %s；直连不劣 %d/%d，配对耗时差 P50 %s；排除旧配置样本 %d 条；证据过期 %t；%s。%s\n", escape(e.Target), e.Pairs, e.Windows, e.SpanHours, e.DirectSuccesses, e.Pairs, e.ProxySuccesses, e.Pairs, milliseconds(e.DirectP50MS), milliseconds(e.ProxyP50MS), milliseconds(e.DirectP95MS), milliseconds(e.ProxyP95MS), e.DirectNoWorse, e.ComparablePairs, milliseconds(e.PairedDeltaP50MS), e.ExcludedSamples, e.Stale, e.Verdict, e.Reason)
		}
	}
	b.WriteString("\n## 数据边界\n\n")
	for _, n := range r.Notes {
		fmt.Fprintf(&b, "- %s\n", n)
	}
	return b.String()
}
func milliseconds(v *int64) string {
	if v == nil {
		return "无可用样本"
	}
	return fmt.Sprintf("%d ms", *v)
}
func escape(s string) string {
	s = strings.ReplaceAll(s, "|", "\\|")
	s = strings.ReplaceAll(s, "\n", " ")
	return strings.ReplaceAll(s, "\r", " ")
}
