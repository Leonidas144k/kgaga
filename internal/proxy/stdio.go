package proxy

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"strings"
	"time"

	"github.com/Leonidas144k/kgaga/internal/delegation"
	"github.com/Leonidas144k/kgaga/internal/keyring"
	"github.com/Leonidas144k/kgaga/internal/mcp"
	"github.com/Leonidas144k/kgaga/internal/passport"
	"github.com/Leonidas144k/kgaga/internal/policy"
	"github.com/Leonidas144k/kgaga/internal/registry"
	"github.com/Leonidas144k/kgaga/internal/revocation"
)

const maxFrame = 2<<20
const maxPassport = 16<<10
const stdioTimeout = 30*time.Second

func stdioBinding(body []byte) passport.RequestBinding {
	// STDIO is not a permitted HTTP method. This separates proof use
	// across transports without introducing a new proof format.
	return passport.RequestBinding{Method:"STDIO",Target:"/mcp",ContentType:"application/json",Body:body}
}

// SignStdioFrame creates a single line: passport TAB proof TAB base64url(body).
// The body must be a single strict JSON-RPC message, without CR or LF.
func SignStdioFrame(key,token string,body []byte) (string,error) {
	if strings.ContainsAny(token,"\t\r\n ") || len(token)==0 || len(token)>maxPassport { return "",errors.New("invalid passport") }
	if _,err:=mcp.InspectStdio(body); err!=nil { return "",err }
	proof,err:=passport.SignRequest(key,token,stdioBinding(body),time.Now())
	if err!=nil { return "",err }
	return token+"\t"+proof+"\t"+base64.RawURLEncoding.EncodeToString(body),nil
}

func parseFrame(line string) (string,string,[]byte,error) {
	bad:=errors.New("invalid signed stdio frame")
	if len(line)>maxFrame { return "","",nil,bad }
	parts:=strings.Split(line,"\t")
	if len(parts)!=3 || len(parts[0])==0 || len(parts[0])>maxPassport || len(parts[1])==0 || len(parts[1])>256 ||
		len(parts[2])>base64.RawURLEncoding.EncodedLen(mcp.MaxPayload) || strings.ContainsAny(parts[0],"\r\n ") { return "","",nil,bad }
	body,err:=base64.RawURLEncoding.Strict().DecodeString(parts[2])
	if err!=nil || len(body)==0 || len(body)>mcp.MaxPayload || base64.RawURLEncoding.EncodeToString(body)!=parts[2] { return "","",nil,bad }
	return parts[0],parts[1],body,nil
}

// RunStdioProxy is an authenticated, one-passport, lockstep development
// transport. A blocked frame terminates the session. The configured child
// runs with the operator's OS privileges; this is not a process sandbox.
func RunStdioProxy(cmdPath string,cmdArgs []string,cfg *policy.Config,audience string,trust *keyring.Store,reg *registry.Store,rev,replay *revocation.Store,in io.Reader,out io.Writer) error {
	if err:=passport.ValidateAudience(audience); err!=nil { return err }
	cfg,err:=cfg.Snapshot()
	if err!=nil { return err }
	limiter,err:=policy.NewRateLimiter(*cfg.RateLimit)
	if err!=nil { return err }
	for _,ready:=range []func()error{trust.Ready,reg.Ready,rev.Ready,replay.Ready} {
		if err:=ready(); err!=nil { return err }
	}
	ctx,cancel:=context.WithCancel(context.Background())
	defer cancel()
	var cmd *exec.Cmd
	var childIn io.WriteCloser
	var childOut io.ReadCloser
	var responses *bufio.Scanner
	defer func(){
		cancel()
		if childIn!=nil { _=childIn.Close() }
		if childOut!=nil { _=childOut.Close() }
		if cmd!=nil { _=cmd.Wait() }
	}()
	scanner:=bufio.NewScanner(in)
	scanner.Buffer(make([]byte,4096),maxFrame+2)
	pinned:=""
	for scanner.Scan() {
		token,proof,body,err:=parseFrame(scanner.Text())
		if err!=nil { return err }
		if pinned!="" && pinned!=token { return errors.New("stdio session passport changed") }
		claims,err:=trust.Verify(token,audience)
		if err!=nil { return errors.New("stdio passport rejected") }
		if err:=rev.Check(claims.ID); err!=nil { return errors.New("stdio revocation check rejected") }
		holder,err:=reg.BoundHolder(claims,audience)
		if err!=nil { return errors.New("stdio agent rejected") }
		if err:=delegation.Check(claims,audience,trust,reg,rev); err!=nil { return errors.New("stdio delegation rejected") }
		nonce,err:=passport.VerifyRequest(proof,token,holder,stdioBinding(body),time.Now())
		if err!=nil { return errors.New("stdio proof rejected") }
		if _,err:=limiter.Allow(claims.AgentID); err!=nil {
			emitAudit(AuditEvent{AgentID:claims.AgentID,PassportID:claims.ID,Method:"STDIO",Decision:"BLOCK",Reason:err.Error()})
			return err
		}
		if err:=replay.Consume(nonce); err!=nil { return errors.New("stdio replay check rejected") }
		info,err:=mcp.InspectStdio(body)
		if err!=nil { return errors.New("stdio MCP message rejected") }
		if ok,_:=cfg.AuthorizeMCP(info.Method,info.ToolName,info.RequiredScope,claims.Scopes); !ok {
			emitAudit(AuditEvent{AgentID:claims.AgentID,PassportID:claims.ID,Method:info.Method,Decision:"BLOCK",Reason:"stdio policy denied"})
			return errors.New("stdio policy denied")
		}
		if cfg.RedactSecrets {
			if err:=policy.InspectPayload(body,true,true); err!=nil { return errors.New("stdio request inspection rejected") }
		}
		if cmd==nil {
			// No execution before authentication and authorization.
			next:=exec.CommandContext(ctx,cmdPath,cmdArgs...)
			next.WaitDelay=2*time.Second
			// Do not automatically relay arbitrary child diagnostic output.
			next.Stderr=io.Discard
			childIn,err=next.StdinPipe()
			if err!=nil { return err }
			childOut,err=next.StdoutPipe()
			if err!=nil { return err }
			if err:=next.Start(); err!=nil { return err }
			cmd=next
			pinned=token
			responses=bufio.NewScanner(childOut)
			responses.Buffer(make([]byte,4096),mcp.MaxPayload+2)
		}
		// Bound child I/O per admitted request. Closing the pipes also
		// interrupts blocked I/O if a descendant retains a descriptor.
		timer:=time.AfterFunc(stdioTimeout,func(){ cancel(); _=childIn.Close(); _=childOut.Close() })
		_,err=childIn.Write(append(bytes.Clone(body),'\n'))
		if err!=nil { timer.Stop(); return fmt.Errorf("stdio child write failed: %w",err) }
		if !info.Notification {
			if !responses.Scan() { timer.Stop(); return errors.New("stdio child response unavailable or oversized") }
			response:=bytes.Clone(responses.Bytes())
			if err:=mcp.ValidateStdioResponse(response,info.ID); err!=nil { timer.Stop(); return errors.New("stdio child response rejected") }
			if cfg.RedactSecrets {
				if err:=policy.InspectPayload(response,true,true); err!=nil { timer.Stop(); return errors.New("stdio response inspection rejected") }
			}
			if !timer.Stop() || ctx.Err()!=nil { return errors.New("stdio child I/O deadline exceeded") }
			// Recheck credential lifecycle before releasing a response.
			current,err:=trust.Verify(token,audience)
			if err!=nil { return errors.New("stdio passport rejected before response") }
			if err:=rev.Check(current.ID); err!=nil { return errors.New("stdio revocation check rejected before response") }
			if _,err:=reg.BoundHolder(current,audience); err!=nil { return errors.New("stdio agent rejected before response") }
			if err:=delegation.Check(current,audience,trust,reg,rev); err!=nil { return errors.New("stdio delegation rejected before response") }
			if _,err:=out.Write(append(response,'\n')); err!=nil { return err }
		} else if !timer.Stop() || ctx.Err()!=nil { return errors.New("stdio child I/O deadline exceeded") }
		emitAudit(AuditEvent{AgentID:claims.AgentID,PassportID:claims.ID,Method:info.Method,Decision:"ALLOW"})
	}
	if err:=scanner.Err(); err!=nil { return errors.New("stdio input frame unavailable or oversized") }
	if cmd==nil { return errors.New("no authorized stdio messages") }
	return nil
}
