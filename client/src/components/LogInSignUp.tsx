import _ from "lodash";
import React, { useContext, useEffect } from "react";
import { Tabs, TabList, Tab, TabPanel, Grid, Alert } from "@mui/joy";
import { StyledSheet } from "./CommonElementStyles";
import LogInForm, { LogInContext } from "./Login";
import SignUpForm, { SignUpContext } from "./Signup";
import { AuthConnectionStatus } from "../AuthClient";
import { CloudOff, WifiOff } from "@mui/icons-material";

type TabProps =  { 
  connectionStatus: AuthConnectionStatus,
  currentTab: number, 
  setCurrentTab: (currentTab: number) => void 
};

export default function LogInSignUp({ connectionStatus, currentTab, setCurrentTab }: TabProps) {
  const { logInData: { submitted: logInSubmitted } } = useContext(LogInContext);
  const { signUpData: { submitted: signUpSubmitted } } = useContext(SignUpContext);

  useEffect(() => setCurrentTab(0), []);

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
        <StyledSheet sx={{ marginTop: "48px" }}>
          <Tabs value={currentTab}
            onChange={(_, value) => setCurrentTab(value as number)}>
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