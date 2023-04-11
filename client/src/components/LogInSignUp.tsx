import _ from "lodash";
import React, { useContext } from "react";
import { Tabs, TabList, Tab, TabPanel, Grid } from "@mui/joy";
import { SubmitResponse } from "../App";
import { StyledSheet, Spacer } from "./CommonElementStyles";
import LogInForm, { LogInContext } from "./Login";
import SignUpForm, { SignUpContext } from "./Signup";
import { Failure } from "../../../shared/commonTypes";

type TabProps =  { currentTab: number, setCurrentTab: (currentTab: number) => void };

export default function LogInSignUp({ currentTab, setCurrentTab }: TabProps) {
  const { logInData: { submitted: logInSubmitted } } = useContext(LogInContext);
  const { signUpData: { submitted: signUpSubmitted } } = useContext(SignUpContext);

  return (
    <React.Fragment>
      <Spacer units={2}/>
      <Grid container sx={{ flexGrow: 1, justifyContent: "center", alignContent: "flex-start" }}>
        <Grid xs={12} sm={8} md={6} lg={4} xl={3}>
          <StyledSheet>
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
      </Grid>
    </React.Fragment>)
}

type LogInSignUpProps = {
  logIn: (response: SubmitResponse) => Promise<Failure>;
  signUp: (response: SubmitResponse) => Promise<Failure>;
  usernameExists: (username: string) => Promise<boolean>;
}