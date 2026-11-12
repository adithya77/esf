package main

import (
	"context"
	"fmt"
	"time"

	"github.com/spf13/cobra"

	"github.com/mitkox/esf/internal/factory"
)

// newWarmCommand manages the warm sandbox pool ([sandbox.warm]). The worker
// keeps the pool filled on its own; these commands are for operators.
func newWarmCommand(configPath *string) *cobra.Command {
	cmd := &cobra.Command{Use: "warm", Short: "Inspect, fill, or drain the warm sandbox pool"}
	withPool := func(run func(context.Context, factory.WarmPoolService) error) func(*cobra.Command, []string) error {
		return func(cmd *cobra.Command, _ []string) error {
			cfg, err := loadConfig(*configPath)
			if err != nil {
				return err
			}
			if !cfg.Sandbox.Warm.Enabled {
				return fmt.Errorf("the warm pool is disabled (sandbox.warm.enabled)")
			}
			ctx := cmd.Context()
			runtime, err := factory.NewRuntime(ctx, factory.RuntimeOptions{Config: cfg})
			if err != nil {
				return err
			}
			defer runtime.Close(ctx)
			acts, err := runtime.Activities()
			if err != nil {
				return err
			}
			return run(ctx, factory.NewWarmPoolService(acts))
		}
	}
	status := func(_ context.Context, pool factory.WarmPoolService) error {
		pools, err := pool.Status()
		if err != nil {
			return err
		}
		for _, p := range pools {
			fmt.Printf("%s  ready=%d filling=%d claiming=%d  %s @ %s\n", p.Key, p.Ready, p.Filling, p.Claiming, p.Source, p.Ref)
		}
		return nil
	}
	cmd.AddCommand(
		&cobra.Command{Use: "status", Short: "Show ready and filling sandboxes per pool", SilenceUsage: true, RunE: withPool(status)},
		&cobra.Command{Use: "fill", Short: "Top every pool up to its size now", SilenceUsage: true, RunE: withPool(func(ctx context.Context, pool factory.WarmPoolService) error {
			started := time.Now()
			if err := pool.Fill(ctx); err != nil {
				return err
			}
			fmt.Printf("filled in %s\n", time.Since(started).Round(time.Second))
			return status(ctx, pool)
		})},
		&cobra.Command{Use: "drain", Short: "Destroy every pooled sandbox", SilenceUsage: true, RunE: withPool(func(ctx context.Context, pool factory.WarmPoolService) error {
			n, err := pool.Drain(ctx)
			fmt.Printf("destroyed %d pooled sandbox(es)\n", n)
			return err
		})},
	)
	return cmd
}
