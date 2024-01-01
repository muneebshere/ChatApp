import _ from "lodash";
import React, { useContext, useEffect, useRef, useState } from "react";
import { Tabs, TabList, Tab, TabPanel, Grid, Alert } from "@mui/joy";
import { StyledSheet } from "./CommonElementStyles";
import LogInForm, { LogInContext } from "./Login";
import SignUpForm, { SignUpContext } from "./Signup";
import { AuthConnectionStatus } from "../AuthClient";
import { CloudOff, WifiOff } from "@mui/icons-material";

type TabProps =  { 
  connectionStatus: AuthConnectionStatus,
  currentTab: number, 
  setCurrentTab: (currentTab: 0 | 1) => void 
};

export default function LogInSignUp({ connectionStatus, currentTab, setCurrentTab }: TabProps) {
  const { logInData: { submitted: logInSubmitted } } = useContext(LogInContext);
  const { signUpData: { submitted: signUpSubmitted } } = useContext(SignUpContext);
  const currentTabRef = useRef<0 | 1>(0);
  const timeoutRef = useRef<number>(null);
  const switchingRef = useRef(false);
  const setCurrentTabLocal = (currentTab: 0 | 1) => setCurrentTab(currentTabRef.current = currentTab);
  const swapTab = () => setCurrentTabLocal(currentTabRef.current === 0 ? 1 : 0);

  useEffect(() => setCurrentTab(0), []);

  function onKey(e: React.KeyboardEvent<HTMLDivElement>, type: "up" | "down") {
    if (timeoutRef.current !== null) {
      window.clearTimeout(timeoutRef.current);
      timeoutRef.current = null;
    }
    if (type === "down" && e.key === "s" && e.altKey && !e.ctrlKey && !e.shiftKey) {
      e.stopPropagation();
      switchingRef.current = true;
      timeoutRef.current = window.setTimeout(() => switchingRef.current = false, 400);
    }
    else if (type === "up" && switchingRef.current && e.key === "s" && !e.ctrlKey && !e.shiftKey) {
      e.stopPropagation();
      swapTab();
    }
    else switchingRef.current = false;
  }

  return (
    <Grid container sx={{ flexGrow: 1, justifyContent: "center", alignContent: "flex-start" }}>
      {(connectionStatus !== "Online") &&
        <Grid xs={12}>
          <Alert
            variant="soft" 
            size="md"
            sx={{ justifyContent: "center" }} 
            color="danger"
            startDecorator={connectionStatus === "ClientOffline" ? <WifiOff/> : <CloudOff/>}>
              {connectionStatus === "ClientOffline" ? "You are offline." : "Cannot reach server."}
          </Alert>
        </Grid>}
      <Grid xs={12} sm={8} md={6} lg={4} xl={3}>
        <StyledSheet sx={{ marginTop: "48px" }}
            onKeyUpCapture={(e) => onKey(e, "up")}
            onKeyDownCapture={(e) => onKey(e, "down")}>
          <Tabs value={currentTab}
            onChange={(_, value: 0 | 1) => setCurrentTabLocal(value)}>
            <TabList variant="outlined">
              <Tab 
                variant={ currentTab === 0 ? "solid" : "plain" }
                color={ currentTab === 0 ? "primary" : "neutral" }
                disabled={ logInSubmitted || signUpSubmitted }>Login</Tab>
              <Tab
                variant={ currentTab === 1 ? "solid" : "plain" }
                color={ currentTab === 1 ? "primary" : "neutral" }
                disabled={ logInSubmitted || signUpSubmitted }>Sign Up</Tab>
            </TabList>
            <TabPanel value={0}>
              <LogInForm/>
            </TabPanel>
            <TabPanel value={1}>
              <SignUpForm/>
            </TabPanel>
          </Tabs>
        </StyledSheet>
      </Grid>
    </Grid>)
}