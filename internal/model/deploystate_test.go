package model

import "testing"

func TestTransitions(t *testing.T) {
	ok := [][2]DeploymentStatus{
		{StatusReceived, StatusValidating},
		{StatusReceived, StatusStartingCandidate},
		{StatusBuilding, StatusSuperseded},
		{StatusHealthChecking, StatusReady},
		{StatusReady, StatusPromotionIntent},
		{StatusDrainingOld, StatusSucceeded},
		{StatusRouterSwitched, StatusFailed},
	}
	for _, c := range ok {
		if !CanTransition(c[0], c[1]) {
			t.Errorf("%s -> %s should be allowed", c[0], c[1])
		}
	}
	bad := [][2]DeploymentStatus{
		{StatusSucceeded, StatusFailed},
		{StatusBuilding, StatusFetching},
		{StatusRouterSwitched, StatusSuperseded},
		{StatusSuperseded, StatusSucceeded},
		{StatusBuilding, StatusReady},
		{StatusFailed, StatusReceived},
	}
	for _, c := range bad {
		if CanTransition(c[0], c[1]) {
			t.Errorf("%s -> %s should be denied", c[0], c[1])
		}
	}
}
