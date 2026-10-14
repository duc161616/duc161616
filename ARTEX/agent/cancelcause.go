package agent

import (
	"context"
	"errors"
	"fmt"
)

// AbortCause names why an agent run's context was cancelled. Every cancellation
// site should attach one so the activity trace can report the real initiator.
type AbortCause struct {
	Code  string
	Short string
	Text  string
}

func (c *AbortCause) Error() string { return c.Text }

func cause(code, short, text string) *AbortCause {
	return &AbortCause{Code: code, Short: short, Text: text}
}

// Causef builds a cause that includes runtime-specific detail.
func Causef(code, short, format string, args ...any) *AbortCause {
	return &AbortCause{Code: code, Short: short, Text: fmt.Sprintf(format, args...)}
}

var (
	// Task-level execution context.
	AbortPausedByUser = cause("paused_by_user", "User paused the task",
		"User paused the task through the task control API (POST /api/tasks/{id}/control, action=pause). This Planner/Worker run was canceled on purpose; running intents go back to the frontier (open) and are reclaimed and rerun from scratch after the task resumes")
	AbortPausedByOrchestrator = cause("paused_by_orchestrator", "Orchestrator Agent paused the task",
		"Orchestrator Agent called the pause_task tool to pause this task. This Planner/Worker run was canceled on purpose; running intents go back to the frontier (open) and rerun after resuming")
	AbortTaskDeleted = cause("task_deleted", "task deleted",
		"task is being deleted (DELETE /api/tasks/{id}); the deletion barrier canceled the task's running Planner, Workers and main Agent; the result of this run will not be used")
	AbortPausedOnReload = cause("paused_on_reload", "backend restored the task's paused state",
		"on startup the backend restored the task's paused state from the database. This run was canceled; normally no Agent is running during restore")
	AbortGoalMet = cause("goal_met", "Planner determined the task goal is met",
		"Planner determined the task goal is met and set the task to done, then canceled the Workers still running; those intents are marked stopped, not failed")
	AbortSettleDrainTimeout = cause("settle_drain_timeout", "timeout wrap-up wait exhausted",
		"after the task timed out, the engine waited for running Workers to wrap up gracefully, but the 90-second drain grace was not enough, so it hard-canceled them; intents are marked exhausted, and facts and assets already written during wrap-up are kept")

	// Per-work context.
	AbortKilledByPlanner = cause("killed_by_planner", "Planner terminated this intent",
		"Planner called kill_work to terminate this intent, usually because the direction went off track or is no longer worth pursuing; the intent is marked stopped and is not reclaimed automatically")
	AbortWorkPausedByUser = cause("work_paused_by_user", "User paused this Worker intent",
		"User paused the running Worker. This call was canceled and the intent became paused; registered intents, facts, findings and activity records are all kept, and it reruns from scratch after resuming")
	AbortWorkCancelledByUser = cause("work_cancelled_by_user", "User deleted this Worker intent",
		"User deleted the running Worker. This call was canceled; once the Worker leaves the write section, the server handles the intent according to the deletion mode the user chose — soft delete only marks it deleted and keeps all output, hard delete cascades and removes the intent and the downstream nodes supported only by it")
	AbortWorkFinished = cause("work_finished", "Worker finished and released its context",
		"Worker finished normally; the engine released its context resources in detachWork. This is not a run interruption; if it appears in an interruption message, cancellation raced with the wrap-up event")
	AbortPausedRaceGuard = cause("paused_race_guard", "new runs refused while task is paused",
		"while the task is paused, the engine refuses to hand out new execution contexts, to stop a race between claim and pause from starting a Worker; claimed intents go back to the frontier")

	// Main Agent and standalone conversation contexts.
	AbortChatStoppedByUser = cause("chat_stopped_by_user", "User stopped this chat turn",
		"User clicked stop and aborted this main Agent or chat Agent run. Activity records already produced are kept; you can keep sending the next message")
	AbortChatPausedWithTask = cause("chat_paused_with_task", "task pause aborted the main Agent chat",
		"when the user paused the task, the running main Agent chat was canceled too. Activity records already produced are kept; this turn's message is not replayed automatically after resuming the task")
	AbortChatTurnFinished = cause("chat_turn_finished", "chat turn finished, context released",
		"this chat turn finished normally; the server is releasing the turn's context resources. This is not a run interruption; if it appears in an interruption message, cancellation raced with the wrap-up event")

	// Process-level and per-run hard backstop.
	AbortShutdown = cause("shutdown", "backend process is shutting down",
		"backend process received SIGINT or SIGTERM and is restarting, updating or shutting down. All running Agents are canceled; intents left running after the restart are reset to open and run again")
	AbortRunHardTimeout = cause("run_hard_timeout", "the per-run hard timeout fallback fired",
		"a single run exceeded its soft wall-clock budget plus extra grace, meaning a model request or some tool did not return for a long time, so the normal turn-boundary wrap-up could not run. Check the last tool call that had not returned before the interruption")
)

// AbortReason resolves the named cause attached to a cancelled run context.
func AbortReason(ctx context.Context) (code, short, text string, ok bool) {
	c := context.Cause(ctx)
	if c == nil {
		return "", "", "", false
	}
	var ac *AbortCause
	if errors.As(c, &ac) {
		return ac.Code, ac.Short, ac.Text, true
	}
	switch {
	case errors.Is(c, context.DeadlineExceeded):
		return "deadline_exceeded", "upstream context reached its deadline",
			"upstream context reached its deadline, but the setter attached no named cause via WithTimeoutCause: " + c.Error(), true
	case errors.Is(c, context.Canceled):
		return "canceled_no_cause", "canceler attached no named cause",
			"upstream context was canceled, but the canceler attached no named cause via context.WithCancelCause; register the cause in agent/cancelcause.go and wire it into that cancellation point", true
	default:
		return "other", firstLine(c.Error(), 80), c.Error(), true
	}
}
