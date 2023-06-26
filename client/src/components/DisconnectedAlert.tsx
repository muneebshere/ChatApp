import React, { useEffect, useRef, useState } from "react";
import { usePrevious } from "@react-hooks-library/core";
import { Alert, Button, CircularProgress, Grid, IconButton, LinearProgress, Option, Select, Sheet, Stack, selectClasses } from "@mui/joy";
import { SxProps, Theme, useMediaQuery } from "@mui/material";
import { ReplayCircleFilledSharp, ReportProblem, CloudOff, WifiOff, MobiledataOffSharp, KeyboardArrowDown, StopCircleSharp } from "@mui/icons-material";
import { DisableSelectTypography } from "./CommonElementStyles";
import { ClientConnectionStatus } from "./Main";
import { Dialog, DialogContent } from "./Dialog";

export type DisconnectedStatus = Exclude<ClientConnectionStatus, "Online">;

type DisconnectedProps = {
  status: DisconnectedStatus;
  countdownTick: {
    subscribe: (tick: (tryingAgainIn: number) => void) => void;
    pause: () => void;
    resume: () => void;
  }
  forceReconnect: () => void;
};

type DisconnectedDisplayProps = {
  fuseBorder: SxProps,
  color: "warning" | "danger",
  icon: JSX.Element,
  message: string,
  buttonAction: string,
};

function unauthenticated(status: DisconnectedStatus): status is "Unauthenticated" {
  return status === "Unauthenticated";
}

function displayProps(status: DisconnectedStatus, tryingAgainIn: number, dots: number, paused: boolean): DisconnectedDisplayProps {
  if (unauthenticated(status)) {
    const fuseBorder: SxProps = {};
    const color = "warning";
    const icon = <ReportProblem sx={{ fontSize: "2.5rem", marginBlock: "auto" }}/>;
    const message = "Encrypted session corrupted.";
    const buttonAction = "Reload page";
    return { fuseBorder, color, icon, message, buttonAction };
  }
  else {
    const fuseBorder: SxProps = 
      tryingAgainIn > 0 
        ? { borderBottomRightRadius: 0, borderBottomLeftRadius: 0 } 
        : {};
    const color = "danger";
    const icon = 
      status === "ClientOffline"
            ? <WifiOff sx={{ fontSize: "2.5rem", marginBlock: "auto" }}/>
            : (status === "ServerUnreachable" 
                ? <CloudOff sx={{ fontSize: "2.5rem", marginBlock: "auto" }}/>
                : <MobiledataOffSharp sx={{ fontSize: "2.5rem", marginBlock: "auto" }}/>);
    const message = 
      (status === "ClientOffline"
          ? "You are offline."
          : (status === "ServerUnreachable"
              ? "Couldn't reach server."
              : "Connection down.")) +
      (paused 
        ? ""
        :(tryingAgainIn <= 0 
          ? ` Reconnecting${'.'.repeat((dots % 5) + 1)}` 
          : ` Attempting to reconnect in ${Math.ceil(tryingAgainIn/1000)}.`));
    const buttonAction = unauthenticated(status) ? "Reload page" : "Retry now";
    return { fuseBorder, color, icon, message, buttonAction };
  }
}

export default function DisconnectedAlert({ status, countdownTick, forceReconnect }: DisconnectedProps) {
  const belowXL = useMediaQuery((theme: Theme) => theme.breakpoints.down("xl"));
  const [tryingAgainIn, setTryingAgainIn] = useState(0);
  const [dots, setDots] = useState(0);
  const [paused, setPaused] = useState(false);
  const waitValueRef = useRef(30);
  const waitTillRef = useRef(1);
  const [warnReload, setWarnReload] = useState(false);
  const intervalRef = useRef<number>(null);
  const previousStatus = usePrevious(status);
  const display = displayProps(status, tryingAgainIn, dots, paused);
  const retrying = tryingAgainIn <= 0;

  useEffect(() => {
    if (unauthenticated(status)) {
      if (waitTillRef.current && Date.now() > waitTillRef.current) {
        setWarnReload(true);
      }
    } 
    else {
      setWarnReload(false); 
      if (retrying && !paused) {
        intervalRef.current = window.setInterval(() => setDots((dots) => dots + 1), 500);
      }
      else {
        setDots(0);
        if (intervalRef.current) {
          window.clearInterval(intervalRef.current);
          intervalRef.current = null;
        }
      }
    }
    if ((previousStatus === "ClientOffline" || previousStatus === "ServerUnreachable") && status === "UnknownConnectivityError") {
      forceReconnect();
    }
  }, [retrying, status, paused]);

  useEffect(() => {
    countdownTick.subscribe(setTryingAgainIn);
    return () => {
      countdownTick.subscribe(null);
      setPaused(false);
      setDots(0);
      setWarnReload(false);
      if (intervalRef.current) {
        window.clearInterval(intervalRef.current);
        intervalRef.current = null;
      }
    }
  }, []);

  const retryButton = (
    <IconButton 
      variant="soft" 
      color={display.color}
      disabled={!unauthenticated(status) && tryingAgainIn === 0}
      onClick={
        unauthenticated(status) 
          ? () => window.history.go() 
          : () => { 
            setPaused(false);
            countdownTick.resume();
            forceReconnect();
          }} 
      sx={{ borderRadius: "100%", padding: "0px", width: "fit-content", margin: "auto" }}>
      <ReplayCircleFilledSharp sx={{ fontSize: "1.8rem" }}/>
    </IconButton>);

  return (
    <div style={{ width: "100%", display: "flex", flexDirection: "row", padding: 0, justifyContent: "center" }}>
      <Stack direction="column" sx={{ width: belowXL ? "100%" : "40%" }}>
        <Alert 
          variant="soft" 
          size="md"
          color={display.color}
          sx={{ justifyContent: "center", ...display.fuseBorder }}>
          <Stack direction="row" spacing={3} sx={{ justifyContent: "space-between", width: "100%" }}>
            {display.icon}
            <Stack direction={belowXL ? "column" : "row"} spacing={belowXL ? 1 : 2} sx={{ width: "fit-content", height: "fit-content", flexWrap: "wrap", alignContent: "center", justifyContent: "center" }} style={{ marginBlock: "auto" }}>
              <DisableSelectTypography level="body1" color={display.color} textAlign="center" style={{ marginBlock: "auto" }}>
                {display.message}
              </DisableSelectTypography>
              {!unauthenticated(status) && !paused && !retrying &&
                <Stack direction="column" spacing={0.2}>
                  <IconButton 
                    variant="soft" 
                    color="danger"
                    onClick={() => {
                      countdownTick.pause();
                      setPaused(true);
                    }} 
                    sx={{ borderRadius: "100%", padding: "0px", width: "fit-content", margin: "auto" }}>
                    <StopCircleSharp sx={{ fontSize: "1.8rem" }}/>
                  </IconButton>
                  <DisableSelectTypography level="body3" color="danger" sx={{ textJustify: "center", textAlign: "center" }}>
                    Stop
                  </DisableSelectTypography>
                </Stack>}
            </Stack>
            <Stack direction="column" spacing={0.2}>
              {unauthenticated(status)
                ? retryButton
                : (retrying
                    ? <div style={{ height: "38px", width: "38px", color: "transparent" }}/>
                    :  (<CircularProgress
                          variant="soft"
                          color="danger"
                          thickness={2} 
                          determinate
                          value={paused ? 0 : 100 - (tryingAgainIn/50)}
                          sx={{ margin: "auto", "--CircularProgress-size": "38px" }}>
                            {retryButton}
                        </CircularProgress>))}
              {unauthenticated(status) || !retrying &&
                <DisableSelectTypography level="body3" color={display.color} sx={{ textJustify: "center", textAlign: "center" }}>
                  {display.buttonAction}
                </DisableSelectTypography>}
            </Stack>
          </Stack>
        </Alert>
        {!unauthenticated(status) && !retrying && !paused && 
        <LinearProgress 
          variant="soft" 
          color="danger"
          thickness={3}
          determinate
          value={100 - (tryingAgainIn/50)}
          sx={{ borderTopRightRadius: 0, borderTopLeftRadius: 0 }}/>}
      </Stack>
      <Dialog
        outsidePress={false}
        controlledOpen={warnReload}
        setControlledOpen={() => {}}>
        <DialogContent>
          <Sheet
            variant="outlined"
            sx={{
              zIndex: 10,
              width: belowXL ? "70vw" : "35vw",
              borderRadius: "md",
              p: 3,
              boxShadow: "lg"}}>
            <div style={{ width: "100%", display: "flex", flexDirection: "row", flexWrap: "wrap", justifyContent: "center", alignContent: "center", marginBottom: "20px" }}>
              <ReportProblem sx={{ marginTop: "4px", marginLeft: "-53.8px", marginRight: "25px", fontSize: "1.8rem", color: "warning.200" }}/>
              <DisableSelectTypography
                textAlign="center"
                component="h2"
                id="modal-title"
                level="h4"
                textColor="warning.200"
                fontWeight="lg"
                mb={1}
                sx={{ margin: 0 }}>
                Encrypted session corrupted.
              </DisableSelectTypography>
            </div>
            <DisableSelectTypography textColor="text.tertiary" textAlign="left" sx={{ marginBottom: "3px" }}>
              The encrypted session with the server has been disrupted, and cannot be re-established until the page is reloaded.
            </DisableSelectTypography>
            <DisableSelectTypography textColor="text.tertiary" textAlign="left" sx={{ marginBottom: "3px" }}>
              <span>
                You may be logged out on reloading if you didn't select 
              </span>
              <span style={{ fontWeight: "bold", whiteSpace: "pre-wrap" }}>
                {" Save password "}
              </span>
              <span>
                when logging in.
              </span>
            </DisableSelectTypography>
            <DisableSelectTypography textColor="text.tertiary" textAlign="left" sx={{ marginBottom: "3px" }}>
              If you choose to continue offline, you won't be able to send or receive messages, or load older messages in your chats.
            </DisableSelectTypography>
            <Stack direction="row" spacing={3} sx={{ paddingTop: "10px", flexWrap: "wrap", alignContent: "center", justifyContent: "center" }}>
              <DisableSelectTypography sx={{ marginBlock: "auto", marginInline: 0 }}>
                Ask me again in:
              </DisableSelectTypography>
              <Select 
                size="sm"
                defaultValue={waitValueRef.current}
                indicator={<KeyboardArrowDown/>}
                onChange={(e, value) => waitValueRef.current = value}
                sx={{
                  height: "20px",
                  paddingInline: "25px",
                  [`& .${selectClasses.indicator}`]: {
                    transition: '0.2s',
                    [`&.${selectClasses.expanded}`]: {
                      transform: 'rotate(-180deg)',
                    },
                  },
                }}>
                <Option value={30}>30s</Option>
                <Option value={60}>1m</Option>
                <Option value={300}>5m</Option>
                <Option value={""}>never</Option>
              </Select>
            </Stack>
            <Grid container direction="row" sx={{ paddingTop: "20px", width: "100%" }}>
              <Grid xs={6} sx={{ display: "flex", flexWrap: "wrap", justifyContent: "center", paddingInline: "45px" }}>
                <Button variant="solid" color="primary" sx={{ flexGrow: 1 }} onClick={ () => {
                    setWarnReload(false);
                    window.history.go(); 
                  } }>
                    Reload page
                </Button>
              </Grid>
              <Grid xs={6} sx={{ display: "flex", flexWrap: "wrap", justifyContent: "center", paddingInline: "45px" }}>
                <Button variant="solid" color="danger" sx={{ flexGrow: 1 }} onClick={ () => {
                  const waitValue = waitValueRef.current;
                  waitTillRef.current = waitValue ? Date.now() + (waitValue * 1000) : null;
                  if (!waitValue) countdownTick.pause();
                  setWarnReload(false);
                  } }>
                  Continue offline
                </Button>
              </Grid>
            </Grid>
          </Sheet>      
        </DialogContent>
      </Dialog>
    </div>
  )
}