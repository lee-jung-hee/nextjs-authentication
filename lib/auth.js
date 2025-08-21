import { Lucia } from "lucia";
// Lucia 핵심 클래스 import. 세션 생성/검증, 쿠키 생성 등을 제공.

import { BetterSqlite3Adapter } from "@lucia-auth/adapter-sqlite";
// Lucia가 DB에 유저/세션을 저장할 때 쓸 어댑터. better-sqlite3 드라이버용.

import db from "./db";
// better-sqlite3로 만든 DB 인스턴스 import. 어댑터에 주입할 커넥션.

import { cookies } from "next/headers";
// Next.js App Router 서버 환경에서 요청/응답 쿠키를 다루는 API.

// --- 어댑터 구성: DB 테이블 매핑 ---
const adapter = new BetterSqlite3Adapter(db, {
  user: "users",
  session: "sessions",
});
// SQLite의 "users" 테이블과 "sessions" 테이블을 Lucia가 쓸 수 있게 연결.
// 스키마가 Lucia가 기대하는 컬럼 구조를 만족해야 동작함.

// --- Lucia 인스턴스 생성: 세션/쿠키 정책 설정 ---
const lucia = new Lucia(adapter, {
  sessionCookie: {
    expires: false,
    // false면 '세션 쿠키'로 발급됨. 브라우저가 종료되면 사라지고,
    // Set-Cookie에 Expires/Max-Age가 안 붙음.

    attributes: {
      secure: process.env.NODE_ENV === "production",
      // production에서만 Secure 플래그를 켠다(HTTPS에서만 전송).
      // httpOnly, sameSite, path 등은 Lucia가 기본값을 채워준다(필요 시 override 가능).
    },
  },
});
// 이 lucia 인스턴스로 세션 발급/검증, 쿠키 문자열 생성 등을 수행.

// --- 세션 생성 + 쿠키 세팅 함수 ---
export async function createAuthSession(userId) {
  const session = await lucia.createSession(userId, {});
  // 주어진 userId로 세션 레코드 생성(DB의 sessions 테이블에 저장).
  // 두 번째 인자 {}는 세션 데이터(커스텀 claims)용. 필요하면 { role: "admin" }처럼 넣을 수 있음. 나중에 result.session.attributes로 읽을 수 있음.

  const sessionCookie = lucia.createSessionCookie(session.id);
  // 위에서 만든 세션의 id를 기반으로 Set-Cookie에 넣을 쿠키 정보를 만든다.
  // { name, value, attributes } 형태를 돌려줌.
  // name: 보통 lucia.sessionCookieName가 가리키는 표준 이름.
  // value: 세션 ID 토큰.
  // attributes: 앞서 설정한 보안 속성(secure/httpOnly/sameSite 등).

  cookies().set(
    sessionCookie.name,
    sessionCookie.value,
    sessionCookie.attributes
  );
  // Next의 응답 쿠키로 실제 Set-Cookie 헤더를 내보냄 → 브라우저 저장.
  // 이제부터 클라이언트는 요청마다 자동으로 이 세션 쿠키를 전송함 → 서버에서 사용자 식별 가능.
  // 이 호출 시점은 반드시 '서버 컴포넌트/서버 액션/Route Handler' 등 서버 컨텍스트여야 함.
}

// 요청마다 세션 검증(로그인 상태 확인 + 쿠키 갱신)
export async function verifyAuth() {
  const sessionCookie = cookies().get(lucia.sessionCookieName);
  // 현재 요청의 쿠키 중에서 Lucia 세션 쿠키 이름으로 된 쿠키를 꺼냄.
  // lucia.sessionCookieName은 위에서 설정한 Lucia 인스턴스가 쓰는 표준 쿠키 이름.

  if (!sessionCookie) {
    return {
      user: null,
      session: null,
    };
  }
  // 세션 쿠키 자체가 없으면 → 로그인되어 있지 않음.

  const sessionId = sessionCookie.value;

  if (!sessionId) {
    return {
      user: null,
      session: null,
    };
  }
  // 쿠키는 있는데 값이 비어있다면 (이상 케이스) → 비로그인 취급.

  const result = await lucia.validateSession(sessionId);
  // 세션 검증 핵심: DB에서 sessionId 레코드를 조회하고 유효/만료 여부 체크.
  // 반환값은 보통 { user, session } 형태:
  // result.user: 유저 객체 (id, email 등)
  // result.session: 세션 객체(없으면 무효/만료)
  // result.session.fresh: 쿠키를 갱신해야 하는 타이밍인지 알려주는 플래그
  // 예) rolling session 정책: 요청이 오면 만료 시간을 연장하고, 그에 맞춰 쿠키도 재발급이 필요할 수 있음.

  try {
    if (result.session && result.session.fresh) {
      const sessionCookie = lucia.createSessionCookie(result.session.id);
      cookies().set(
        sessionCookie.name,
        sessionCookie.value,
        sessionCookie.attributes
      );
    }
    // 세션이 유효하고 fresh=true면 → 쿠키를 재발급(갱신) 해서 만료 연장/속성 최신화.
    // 이렇게 해야 롤링 세션(활동할수록 세션 유지)이 정확히 동작.

    if (!result.session) {
      const sessionCookie = lucia.createBlankSessionCookie();
      cookies().set(
        sessionCookie.name,
        sessionCookie.value,
        sessionCookie.attributes
      );
    }
  } catch {}
  // 세션이 무효/만료라면 → 빈(blank) 세션 쿠키를 만들어 클라이언트의 쿠키를 삭제해야 함.
  // 주의: 지금 코드는 blank 쿠키를 만들기만 하고, cookies().set(...)을 안 해서 실제 삭제가 안 됨.
  //    반드시 cookies().set(sessionCookie.name, sessionCookie.value, sessionCookie.attributes) 호출해야 브라우저 쿠키 삭제됨. (아래에서 수정 코드 제공)

  return result;
  // 컨트롤러/라우트/서버 컴포넌트에서 const { user, session } = await verifyAuth()처럼 써서 로그인 상태 분기하면 됨.
}

export async function destroySession() {
  const { session } = await verifyAuth();
  if (!session) {
    return {
      error: "Unauthorized!",
    };
  }

  await lucia.invalidateSession(session.id);

  const sessionCookie = lucia.createBlankSessionCookie();
  cookies().set(
    sessionCookie.name,
    sessionCookie.value,
    sessionCookie.attributes
  );
}
/*
lucia 메서드, 프로퍼티
1) lucia.createSession(userId, attributes?)
    역할: DB에 새 세션 레코드를 생성.
    인자
    userId: string – 로그인 성공한 유저 ID
    attributes?: Record<string, unknown> – 세션에 붙일 커스텀 속성(예: { role: "admin" })
    반환: Session 객체 (예: { id, userId, fresh, ... })
    언제: 로그인 직후, 또는 2FA 통과 후.
    비고: fresh는 “이번 요청에서 만료 연장/재발급이 필요한지” 판단에 쓰임.  ￼

⸻

2) lucia.createSessionCookie(sessionIdOrSession)
    역할: Set-Cookie에 넣을 세션 쿠키 객체 생성.
    인자: 보통 session.id를 전달(일부 버전은 Session 자체도 허용).
    반환: Cookie 객체 { name, value, attributes, serialize() }
    언제: 세션을 만들었거나(createSession), 세션이 갱신되어 쿠키를 재발급해야 할 때.
    비고: attributes에 httpOnly/secure/sameSite/maxAge 등이 들어있음(설정값 기반). serialize()로 직접 헤더 문자열을 뽑을 수도 있음.  ￼ ￼

⸻

3) lucia.createBlankSessionCookie()
    역할: 세션 쿠키 삭제용 쿠키 객체 생성(만료된 Set-Cookie).
    반환: Cookie 객체 { name, value, attributes } (삭제되도록 값/만료가 설정됨)
    언제: 세션이 무효/만료되었거나 로그아웃할 때 반드시 내려서 브라우저 쿠키 삭제.
    주의: 단순히 객체만 만들면 의미 없음. 반드시 cookies().set(...)로 응답에 실어야 삭제됨.  ￼

⸻

4) lucia.validateSession(sessionId)
    역할: 세션 id로 세션 유효성 검증(DB 조회, 만료/무효 여부 체크).
    반환: { user: User | null, session: Session | null }
    session.fresh === true 라면 쿠키 재발급 필요 신호 → createSessionCookie()로 새 쿠키 내려야 함.
    언제: 매 요청마다 “누구인지(로그인 상태인지)” 판별할 때.
    실수 포인트: 무효/만료면 blank 쿠키 내려서 브라우저 쿠키도 지워야 함.  ￼ ￼

⸻

5) lucia.sessionCookieName
    역할: Lucia가 사용하는 세션 쿠키 이름을 알려주는 프로퍼티.
    언제: 프레임워크의 쿠키 API로 cookies().get(lucia.sessionCookieName) 같은 접근할 때.
    비고: 직접 문자열 하드코딩하지 말고 이것 사용. 버전/설정 변화에 안전.  ￼

⸻
아직 나오지 않은 자주 같이 쓰는 메서드/유틸 (실무 필수)

6) lucia.invalidateSession(sessionId)
    역할: 해당 세션 1개를 무효화(DB에서 폐기/만료 처리).
    언제: 로그아웃(특정 기기), 보안 이슈 시 강제 만료.
    보통 같이: createBlankSessionCookie() 내려서 브라우저 쿠키도 삭제.

7) lucia.invalidateUserSessions(userId)
    역할: 해당 유저의 모든 세션을 무효화(다중 기기 로그아웃).
    언제: 비밀번호 변경/계정 탈취 의심 등 보안 조치.

8) lucia.readSessionCookie(headerValue) (버전에 따라 제공 위치/이름 다를 수 있음)
    역할: Cookie 헤더 문자열에서 세션 쿠키 값을 파싱.
    언제: 프레임워크 추상화가 없거나(예: 순수 Fetch 핸들러), 직접 파싱이 필요할 때.
    참고: Next.js App Router에서는 cookies()를 쓰는 게 보통 더 간편. v3 가이드에도 쿠키 읽고 validateSession() 하라고 명시.  ￼

9) Bearer 토큰 관련 (validateBearerToken 류)
    역할: 헤더의 Bearer 토큰(세션 id)을 검증.
    언제: 모바일 앱/SPA에서 쿠키 대신 토큰 방식으로 세션을 들고 다니는 아키텍처.
    웹앱은 보통 쿠키가 권장(자동 전송 + CSRF에 sameSite).  ￼
*/
