# CTF Lab Hub UI Component Manifest

## Global / Shell (All Pages)

- **Sidebar** (shadcn) — `npx shadcn@latest add sidebar` — Global navigation rail with lab tracks, user progress, theme toggle. Pair with Framer Motion `layout` prop for collapse/expand width transitions + `AnimatePresence` for nested menu items.
- **NavigationMenu** (shadcn) — `npx shadcn@latest add navigation-menu` — Top bar with track categories (Web, Pwn, Crypto, Reversing, Forensics). Pair with `motion.div` + `whileHover={{ y: -2 }}` spring for menu item lift.
- **Command** (shadcn) — `npx shadcn@latest add command` — Global cmd+k palette for jumping between labs, docs, scoreboard. Pair with `AnimatePresence` for open/close + `initial={{ scale: 0.95, opacity: 0 }}` spring entrance.
- **Sonner** (shadcn) — `npx shadcn@latest add sonner` — Toast notifications for flag submissions, lab unlocks, hint reveals. Built-in motion; wrap custom content in `motion.div` with `layout` for stack reorder.
- **Tooltip** (shadcn) — `npx shadcn@latest add tooltip` — Hover hints on icons, difficulty badges, terminal shortcuts. Pair with Radix's built-in animation or override via `motion.div` scale spring.
- **DropdownMenu** (shadcn) — `npx shadcn@latest add dropdown-menu` — Profile menu, lab filter menu, container actions (restart/reset). Pair with `AnimatePresence` + slide-fade `y: -8 → 0`.
- **Dialog** (shadcn) — `npx shadcn@latest add dialog` — Confirm reset container, submit flag modal. Pair with `AnimatePresence` (mandatory for exit anim) + backdrop `opacity` tween + content `scale` spring.
- **Sheet** (shadcn) — `npx shadcn@latest add sheet` — Slide-in lab handbook, hint drawer, terminal side panel. Pair with `AnimatePresence` + `x: '100%' → 0` spring (stiffness 300, damping 30).
- **ThemeSwitcher** (21st.dev) — `npx shadcn@latest add https://21st.dev/r/serafimcloud/theme-switcher` — Dark/light/hacker-green tri-mode toggle. Pair with `layout` prop on the sliding thumb + `motion.circle` for icon crossfade.
- **AnimatedBackground** (21st.dev) — `npx shadcn@latest add https://21st.dev/r/aceternity/aurora-background` — Ambient shader-like backdrop for hero + auth pages. Pair with `motion.div` `animate` loop on gradient position.

---

## Landing / Marketing Page (`/`)

- **Hero-Highlight** (21st.dev) — `npx shadcn@latest add https://21st.dev/r/aceternity/hero-highlight` — Headline "Break in. Learn how." with highlighted keywords. Pair with Framer Motion `motion.span` staggered `opacity` + `y` on the highlight sweep.
- **TextGenerateEffect** (21st.dev / Aceternity) — `npx shadcn@latest add https://21st.dev/r/aceternity/text-generate-effect` — Typewriter subtitle for tagline. Pair with `motion.span` per-word `opacity: 0 → 1` with stagger 0.05s.
- **BackgroundBeams** (21st.dev / Aceternity) — `npx shadcn@latest add https://21st.dev/r/aceternity/background-beams` — SVG beams in hero. Pair with `motion.svg` path `pathLength: 0 → 1` on scroll-into-view.
- **BentoGrid** (21st.dev / Aceternity) — `npx shadcn@latest add https://21st.dev/r/aceternity/bento-grid` — "What you'll learn" feature grid (web exploitation / bin-exp / crypto / forensics tiles). Pair with `layout` prop + `whileHover={{ scale: 1.02 }}` spring per tile.
- **InfiniteMovingCards** (21st.dev / Aceternity) — `npx shadcn@latest add https://21st.dev/r/aceternity/infinite-moving-cards` — Testimonials / featured CTF wins ticker. Pair with `motion.div` `animate={{ x: [0, -width] }}` linear loop.
- **AnimatedTooltip** (21st.dev / Aceternity) — `npx shadcn@latest add https://21st.dev/r/aceternity/animated-tooltip` — Team / top solvers avatar stack. Pair with `AnimatePresence` + spring `rotate` on hover.
- **Button** (shadcn) — `npx shadcn@latest add button` — "Start hacking" primary CTA + secondary "View labs". Pair with Framer Motion **magnetic** wrapper (`motion.div` `x`/`y` following mouse delta with spring) + `whileTap={{ scale: 0.96 }}`.
- **MovingBorder** (21st.dev / Aceternity) — `npx shadcn@latest add https://21st.dev/r/aceternity/moving-border` — "Enter the lab" gradient-border CTA. Pair with `motion.path` on the SVG border traveler.

---

## Lab Catalog / Track Grid (`/labs`)

- **Card** (shadcn) — `npx shadcn@latest add card` — Individual lab tile (title, difficulty, category, solves count). Pair with `layout` for filter re-flow + `whileHover={{ y: -4, scale: 1.02 }}` spring.
- **HoverEffect / CardHoverEffect** (21st.dev / Aceternity) — `npx shadcn@latest add https://21st.dev/r/aceternity/card-hover-effect` — Grid where hovered card lifts, siblings dim. Pair with `AnimatePresence` on the hover-follower background blob + `layoutId="hoverBg"`.
- **Badge** (shadcn) — `npx shadcn@latest add badge` — Difficulty (easy/med/hard/insane), category tags, "new" / "solved" flags. Pair with `motion.span` `initial={{ scale: 0 }}` spring on mount + `layout` for wrap changes.
- **Tabs** (shadcn) — `npx shadcn@latest add tabs` — Switch between All / Web / Pwn / Crypto / Rev / Forensics. Pair with `layoutId="tabIndicator"` on the active underline for shared-element slide.
- **Select** (shadcn) — `npx shadcn@latest add select` — Sort by (newest / difficulty / solves / points). Pair with `AnimatePresence` slide-fade menu.
- **Input** (shadcn) — `npx shadcn@latest add input` — Search labs by name/tag. Pair with `motion.div` `layout` on the results grid so filtered items animate into new positions.
- **Checkbox** (shadcn) — `npx shadcn@latest add checkbox` — Filter checkboxes (show-solved, show-locked). Pair with `motion.svg` path `pathLength` for the checkmark draw.
- **Slider** (shadcn) — `npx shadcn@latest add slider` — Difficulty range filter. Pair with spring on the thumb `scale` while dragging.
- **Pagination** (shadcn) — `npx shadcn@latest add pagination` — Page nav for large catalogs. Pair with `AnimatePresence mode="wait"` on the grid crossfade.
- **Skeleton** (shadcn) — `npx shadcn@latest add skeleton` — Loading placeholders while fetching lab list. Pair with `motion.div` shimmer `animate={{ backgroundPositionX: ['0%', '100%'] }}` loop.
- **AnimatedList** (21st.dev / Magic UI) — `npx shadcn@latest add https://21st.dev/r/magicui/animated-list` — "Recently solved" side feed. Pair with `AnimatePresence` + `layout` for new-item slide-in-and-push.

---

## Lab Detail / Challenge Page (`/labs/[slug]`)

- **Breadcrumb** (shadcn) — `npx shadcn@latest add breadcrumb` — Track > Category > Lab name. Pair with `motion.span` stagger fade-in on route change.
- **Tabs** (shadcn) — `npx shadcn@latest add tabs` — Description / Handbook / Hints / Writeup (post-solve). Pair with `layoutId` for indicator slide + `AnimatePresence mode="wait"` on panel crossfade.
- **Card** (shadcn) — `npx shadcn@latest add card` — Challenge metadata panels (points, first blood, solve count). Pair with `layout` for expand on "show more".
- **Progress** (shadcn) — `npx shadcn@latest add progress` — Container-boot progress, hint-cost progress. Pair with `motion.div` on the fill using spring transition when `value` changes.
- **Alert** (shadcn) — `npx shadcn@latest add alert` — Container status (running / rebuilding / expired). Pair with `AnimatePresence` slide-down `y: -20 → 0`.
- **Button** (shadcn) — `npx shadcn@latest add button` — "Spawn instance" / "Extend time" / "Reset". Pair with `whileTap` scale + magnetic pull on primary spawn.
- **Input** (shadcn) — `npx shadcn@latest add input` — Flag submission field (`flag{...}`). Pair with `motion.div` shake `animate={{ x: [0,-8,8,-6,6,0] }}` on wrong-flag error.
- **Form** (shadcn) — `npx shadcn@latest add form` — RHF wrapper for flag submit + notes. Pair with `AnimatePresence` on field-level error messages `height: 0 → auto`.
- **Accordion** (shadcn) — `npx shadcn@latest add accordion` — Progressive hint reveal ("cost N points"). Pair with `motion.div` `height` spring + `AnimatePresence` on hint body.
- **HoverCard** (shadcn) — `npx shadcn@latest add hover-card` — Preview author / first-blood user on hover. Pair with `AnimatePresence` scale + fade.
- **Dialog** (shadcn) — `npx shadcn@latest add dialog` — "Confirm hint purchase (-25 pts)" modal. Pair with `AnimatePresence` backdrop + content spring.
- **CodeBlock / CodeComparison** (21st.dev / Magic UI) — `npx shadcn@latest add https://21st.dev/r/magicui/code-comparison` — Vulnerable-vs-patched snippet in the writeup tab. Pair with `motion.div` slide split-reveal + `layoutId` for shared line highlights.
- **Confetti** (21st.dev / Magic UI) — `npx shadcn@latest add https://21st.dev/r/magicui/confetti` — Fires on correct flag. Pair with `AnimatePresence` on the overlay + Framer's `useAnimate` for the celebratory badge pop.
- **NumberTicker** (21st.dev / Magic UI) — `npx shadcn@latest add https://21st.dev/r/magicui/number-ticker` — Point-award count-up on solve. Pair with Framer `useMotionValue` + `animate()` easeOut.

---

## In-Browser Terminal / Container View (`/labs/[slug]/terminal`)

- **ResizablePanel** (shadcn) — `npx shadcn@latest add resizable` — Split between handbook / terminal / target-app iframe. Pair with `motion.div` on the handle `whileHover={{ scaleX: 1.5 }}` spring.
- **ScrollArea** (shadcn) — `npx shadcn@latest add scroll-area` — Handbook + terminal scroll containers. Pair with `motion.div` fade-mask on scroll edges using `useScroll` + `useTransform`.
- **Tabs** (shadcn) — `npx shadcn@latest add tabs` — Multiple terminal sessions / target views. Pair with `layoutId` on the active tab background pill.
- **Sheet** (shadcn) — `npx shadcn@latest add sheet` — Slide-out handbook. Pair with `AnimatePresence` + x-spring.
- **Terminal** (21st.dev / Magic UI) — `npx shadcn@latest add https://21st.dev/r/magicui/terminal` — Styled xterm-like output block for lab intro / expected commands. Pair with `motion.span` typewriter reveal + blinking-caret `animate={{ opacity: [0,1,0] }}` loop.
- **AnimatedBeam** (21st.dev / Magic UI) — `npx shadcn@latest add https://21st.dev/r/magicui/animated-beam` — Draws a beam from "your machine" node to "target container" node in the topology mini-map. Pair with `motion.svg` `pathLength` scroll-linked animation.
- **DotPattern** (21st.dev / Magic UI) — `npx shadcn@latest add https://21st.dev/r/magicui/dot-pattern` — Terminal-panel subtle background. Pair with `motion.circle` opacity ripples on focus.
- **Badge** (shadcn) — `npx shadcn@latest add badge` — TTL countdown, container health. Pair with `motion.span` color-change spring when TTL < 5 min.
- **Toaster/Sonner** (shadcn) — already installed globally — Emits "container ready" / "flag accepted". Pair with `AnimatePresence` + `layout` for stack.

---

## Scoreboard / Leaderboard (`/scoreboard`)

- **Table** (shadcn) — `npx shadcn@latest add table` — Rank / user / solves / points / last-solve. Pair with `layout` on rows for real-time re-order + `AnimatePresence` for enter/exit + spring `layoutId` per row.
- **Avatar** (shadcn) — `npx shadcn@latest add avatar` — User avatars in table + top-3 pedestal. Pair with `layoutId="avatar-{userId}"` for shared-element promotion to pedestal.
- **Chart** (shadcn) — `npx shadcn@latest add chart` — Score-over-time line chart for top N. Pair with `motion.path` `pathLength: 0 → 1` on mount + `motion.circle` for data-point pop-in.
- **Tabs** (shadcn) — `npx shadcn@latest add tabs` — Global / Weekly / Team leaderboards. Pair with `layoutId` indicator.
- **HoverCard** (shadcn) — `npx shadcn@latest add hover-card` — Player summary on row hover. Pair with `AnimatePresence` scale-fade.
- **AnimatedList** (21st.dev / Magic UI) — `npx shadcn@latest add https://21st.dev/r/magicui/animated-list` — Live "first blood" ticker. Pair with `AnimatePresence layout` + slide+push.
- **NumberTicker** (21st.dev / Magic UI) — `npx shadcn@latest add https://21st.dev/r/magicui/number-ticker` — Live point totals per row. Pair with `useMotionValue` spring on value change.
- **BorderBeam** (21st.dev / Magic UI) — `npx shadcn@latest add https://21st.dev/r/magicui/border-beam` — Traveling gradient border around #1 rank card. Pair with `motion.div` continuous rotation via `animate` loop.
- **Marquee** (21st.dev / Magic UI) — `npx shadcn@latest add https://21st.dev/r/magicui/marquee` — Ticker of recent solves across top. Pair with linear `animate={{ x }}` infinite loop.

---

## Track / Learning Path Map (`/tracks/[slug]`)

- **Card** (shadcn) — `npx shadcn@latest add card` — Node cards on the path (each lab step). Pair with `layout` + `whileHover` spring.
- **Progress** (shadcn) — `npx shadcn@latest add progress` — Track completion %. Pair with `motion.div` fill spring.
- **AnimatedBeam** (21st.dev / Magic UI) — `npx shadcn@latest add https://21st.dev/r/magicui/animated-beam` — Draws edges between path nodes (prereq graph). Pair with **`motion.svg` path** `pathLength` scroll-linked reveal per edge.
- **Timeline** (21st.dev / Aceternity) — `npx shadcn@latest add https://21st.dev/r/aceternity/timeline` — Vertical progression view of the track. Pair with `useScroll` + `useTransform` for scroll-linked node lighting.
- **Tooltip** (shadcn) — already installed — Node status (locked / unlocked / solved).

---

## Profile / Achievements (`/u/[handle]`)

- **Avatar** (shadcn) — already installed.
- **Card** (shadcn) — Stats cards (solves, points, rank). Pair with `layout` + count-up on numbers.
- **Badge** (shadcn) — Earned achievement badges. Pair with `motion.div` `initial={{ scale: 0, rotate: -30 }}` spring stagger on grid mount.
- **Tabs** (shadcn) — Overview / Solves / Achievements / Writeups. Pair with `layoutId` indicator.
- **Chart** (shadcn) — Category radar / activity heatmap. Pair with `motion.polygon` `points` interpolation on data change.
- **Calendar** (shadcn) — `npx shadcn@latest add calendar` — Activity heatmap (GitHub-style contrib graph). Pair with `motion.rect` per-cell stagger fade-in.
- **Separator** (shadcn) — `npx shadcn@latest add separator` — Section dividers. Pair with `motion.div` `scaleX: 0 → 1` on view.
- **3D Card / CardContainer** (21st.dev / Aceternity) — `npx shadcn@latest add https://21st.dev/r/aceternity/3d-card-effect` — Featured achievement showcase with tilt. Pair with Framer `useMotionValue` mouse-x/y → `rotateX`/`rotateY` spring.
- **EvervaultCard** (21st.dev / Aceternity) — `npx shadcn@latest add https://21st.dev/r/aceternity/evervault-card` — "Legendary" achievement reveal on hover (character-scramble). Pair with `AnimatePresence` on the mask + `useMotionValue` mouse tracking.

---

## Auth (`/login`, `/signup`)

- **Card** (shadcn) — Auth card wrapper. Pair with `initial={{ y: 20, opacity: 0 }}` spring on mount.
- **Form / Input / Label / Button** (shadcn) — Standard auth fields.
- **InputOTP** (shadcn) — `npx shadcn@latest add input-otp` — 2FA code entry. Pair with `motion.div` per-slot `scale` bump on fill + shake on error.
- **Separator** (shadcn) — "or continue with" divider.
- **Alert** (shadcn) — Error states. Pair with `AnimatePresence` `height` collapse.
- **BackgroundBeams / Spotlight** (21st.dev / Aceternity) — `npx shadcn@latest add https://21st.dev/r/aceternity/spotlight` — Ambient auth backdrop. Pair with `motion.div` mouse-follow spotlight via `useMotionValue`.

---

## Admin / Instructor Console (`/admin`)

- **DataTable** (shadcn, from `table` + `tanstack/react-table`) — `npx shadcn@latest add table` — Users, labs, container fleet. Pair with `layout` on rows + `AnimatePresence` for row add/remove.
- **Dialog** (shadcn) — CRUD modals. Pair with `AnimatePresence` + spring.
- **Form** (shadcn) — Lab-authoring form (title, category, points, container image, flag). Pair with `AnimatePresence` on field errors.
- **Textarea** (shadcn) — `npx shadcn@latest add textarea` — Lab handbook markdown editor.
- **Select** (shadcn) — Category, difficulty pickers.
- **Switch** (shadcn) — `npx shadcn@latest add switch` — Publish toggle. Pair with `motion.div` `layout` on the sliding thumb.
- **Tabs** (shadcn) — Labs / Users / Containers / Metrics.
- **Chart** (shadcn) — Container-uptime, solve-rate charts.
- **AlertDialog** (shadcn) — `npx shadcn@latest add alert-dialog` — Destructive confirm (delete lab, ban user). Pair with `AnimatePresence` + spring.

---

## GSAP Presets (from ui-ux-pro-max catalog) that fit

- **scrollTrigger-pin** — Pin the lab-handbook side panel while the terminal scrolls independently on `/labs/[slug]/terminal`. Also pin the hero screen on landing until the "features" bento enters.
- **scrollTrigger-scrub** — Scrub the `AnimatedBeam` edges on the track-map page so path progress reveals as the user scrolls.
- **split-text** — Landing hero headline split into chars/words with staggered `y` + `opacity` reveal; also for lab-title reveal on lab-detail mount.
- **magnetic-cursor** — Wrap primary CTAs ("Start hacking", "Spawn instance", "Submit flag") for cursor-magnet pull.
- **cursor-follower / spotlight-cursor** — Global hacker-mode cursor blob that intensifies on interactive elements; also drives the `Spotlight` on auth pages.
- **flip-list** — Scoreboard row re-orders on live rank change (GSAP FLIP for buttery layout transitions, complementing Framer's `layout` where FLIP timing is finer).
- **counter / count-up** — Points, solves, container-TTL number tickers (redundant with `NumberTicker` — pick one per surface; GSAP for high-precision easing).
- **stagger-grid** — Lab-catalog cards stagger in on first render; achievement badges on profile.
- **draw-svg (drawSVG)** — Progress rings, terminal boot-line SVG paths, track-map edges.
- **morph-svg (morphSVG)** — Rabbit-sprite tail flick / ear morph fallback if not using Rive (see below); also for icon state morphs (lock → unlock on lab unlock).
- **scramble-text** — "Decrypting..." effect on flag submission + achievement name reveals; hero subtitle wobble.
- **glitch-text** — Occasional glitch on the hero title and on "wrong flag" error label.
- **marquee** — Recent-solves ticker on scoreboard (if not using Magic UI's Marquee).
- **parallax-layers** — Landing hero background beams + foreground copy scroll at different rates.
- **reveal-mask (clip-path reveal)** — Section headers on landing; achievement unlock overlay.
- **hover-tilt (3D tilt)** — Featured achievement 3D card (complements Aceternity 3D-card).
- **timeline-sequence** — Onboarding walkthrough on first-visit (multi-step highlight sequence over the shell).
- **path-motion (motionPath)** — Rabbit hopping along the track-map path from node to node.
- **elastic-bounce** — Flag-accepted badge pop; container-ready toast entrance.

---

## Rabbit Sprite: Rive vs Lottie

**Recommendation: Rive.** Reasons:

- Lottie is playback-only (segments/markers), no true state machine — every state transition needs JS orchestration and interruptions look glitchy.
- Rive has first-class **state machines** with inputs (booleans, triggers, numbers), interruption blending, and listeners — exactly the shape of a mascot reacting to app events (solve, fail, hint, idle).
- Runtime is ~90KB (rive-react), one `.riv` binary carries art + logic; Lottie needs JSON + a controller layer you'd write yourself.
- Interactivity (hover, click, cursor-follow eyes) is declarative in Rive; in Lottie you'd chain segments manually.
- Lottie is preferable only if the animator refuses Rive tooling or the sprite is truly one-shot / decorative.

### Rive State Machine: `RabbitBrain`

**Inputs**

- `state` (Number, enum-style) — high-level mode
- `trigger_solve` (Trigger)
- `trigger_fail` (Trigger)
- `trigger_hint` (Trigger)
- `trigger_levelup` (Trigger)
- `cursor_x` / `cursor_y` (Number, 0–1) — for eye tracking
- `typing` (Boolean) — user typing in flag field
- `container_booting` (Boolean)
- `mood` (Number, 0–100) — cumulative "streak" mood

**States**

- `Idle_Breathing` — default; slow chest bob, occasional blink; entered on mount and after any transient state settles.
- `Idle_Looking` — eyes track `cursor_x/y`; auto-blended over `Idle_Breathing`.
- `Alert_EarsUp` — ears perk on cmd+k / focus events (hovering a lab card).
- `Thinking_Ponder` — paw-to-chin loop while `typing=true` on the flag input.
- `Waiting_Spinner` — light foot-tap loop while `container_booting=true`.
- `Sniff_Curious` — nose twitch when hovering a locked lab or unread hint.
- `Celebrate_Hop` — one-shot hop + confetti-tail on `trigger_solve`; exits back to `Idle_Breathing`.
- `Celebrate_BigWin` — bigger multi-hop + spin on `trigger_levelup` (rank up / track complete).
- `Sad_Wilt` — ears drop, slow shake on `trigger_fail` (wrong flag); auto-recover after 1.5s.
- `Peek_Hint` — pulls a scroll into frame on `trigger_hint`.
- `Sleep_Curled` — after `mood` low + user idle > 60s; wakes on any input.
- `Hidden_Offscreen` — hop offscreen when panel closes (route change); re-enters on next mount.

**Transitions (key ones)**

- Any → `Celebrate_Hop` on `trigger_solve` (interrupts).
- Any → `Sad_Wilt` on `trigger_fail` → auto `Idle_Breathing` after `exitTime`.
- `Idle_*` → `Thinking_Ponder` when `typing=true`; reverse when false.
- `Idle_*` → `Waiting_Spinner` when `container_booting=true`.
- `Idle_Breathing` → `Sleep_Curled` when `mood < 20` and idle timer elapses.
- `Celebrate_Hop` → `Celebrate_BigWin` if `trigger_levelup` fires within blend window.

**Integration**

- `@rive-app/react-canvas`, load `rabbit.riv`, expose a `useRiveInputs()` hook. Fire `trigger_solve` from the flag-submit success handler, `trigger_fail` from the error handler, drive `cursor_x/y` from a global `useMotionValue` pair, and toggle `typing` / `container_booting` from the relevant page state. The sprite lives in a fixed corner slot in the shell (bottom-right, above the toaster) so it persists across route changes.
