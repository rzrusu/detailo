# Detailo.ro — Development Plan

> **Auto-Detailing Shop Owner CMS** — A production-grade, microservices-based platform that enables auto-detailing shop owners to manage their business, services, and staff while providing customers with a seamless Calendly-style booking experience.

---

## Table of Contents

1. [Project Overview](#1-project-overview)
2. [Architecture](#2-architecture)
3. [Technology Stack](#3-technology-stack)
4. [Feature Specifications](#4-feature-specifications)
5. [Microservice Breakdown](#5-microservice-breakdown)
6. [Database Design](#6-database-design)
7. [API Design](#7-api-design)
8. [Frontend Architecture](#8-frontend-architecture)
9. [Infrastructure & DevOps](#9-infrastructure--devops)
10. [Observability](#10-observability)
11. [Security](#11-security)
12. [Development Phases](#12-development-phases)
13. [Testing Strategy](#13-testing-strategy)

---

## 1. Project Overview

### 1.1 Problem Statement

Auto-detailing shop owners lack affordable, purpose-built software to manage their daily operations. They typically juggle spreadsheets, phone calls, and social-media DMs to handle bookings — leading to double-bookings, no-shows, and lost revenue. Customers, in turn, have no easy way to discover services, compare pricing, or self-schedule appointments.

### 1.2 Solution

**Detailo** is a cloud-native, multi-tenant CMS platform that gives every shop owner:

- A **management dashboard** to configure their business profile, services, staff, and working hours.
- A **public booking page** (unique URL per shop) where customers can browse services, view a photo gallery, read reviews, and book appointments through an interactive calendar.
- A **mini-CRM** to track customers, their vehicles, and booking history.
- An **analytics dashboard** with revenue, booking, and customer-retention insights.

### 1.3 User Roles

| Role | Description |
|---|---|
| **Owner** | Registers an account, sets up shop profile, manages everything. Full admin access. |
| **Staff / Detailer** | Invited by owner. Can view their schedule, mark jobs as complete, upload gallery photos. |
| **Customer** | Browses the public page, books appointments, leaves reviews. Lightweight account (email-based). |

---

## 2. Architecture

### 2.1 High-Level Architecture

```
┌──────────────────────────────────────────────────────────────────────────┐
│                              CLIENTS                                     │
│                  React SPA  ·  Mobile (future)                           │
└──────────────────────┬───────────────────────────────────────────────────┘
                       │ HTTPS
                       ▼
              ┌─────────────────┐
              │   API Gateway   │  (Spring Cloud Gateway)
              │   Rate-limiting │
              │   Auth routing  │
              └────────┬────────┘
                       │
        ┌──────────────┼──────────────────────────────────────┐
        │              │              │              │         │
        ▼              ▼              ▼              ▼         ▼
 ┌────────────┐ ┌────────────┐ ┌───────────┐ ┌──────────┐ ┌──────────┐
 │  Identity  │ │   Shop     │ │  Booking  │ │ Customer │ │  Media   │
 │  Service   │ │  Service   │ │  Service  │ │ Service  │ │ Service  │
 └──────┬─────┘ └─────┬──────┘ └─────┬─────┘ └────┬─────┘ └────┬─────┘
        │              │              │             │            │
        ▼              ▼              ▼             ▼            ▼
 ┌────────────┐ ┌────────────┐ ┌───────────┐ ┌──────────┐ ┌──────────┐
 │ identity_db│ │  shop_db   │ │booking_db │ │customer_db│ │ media_db │
 └────────────┘ └────────────┘ └───────────┘ └──────────┘ └──────────┘

                       │ Events (Kafka / RabbitMQ)
        ┌──────────────┼──────────────┐
        ▼              ▼              ▼
 ┌────────────┐ ┌────────────┐ ┌────────────┐
 │Notification│ │  Review    │ │ Analytics  │
 │  Service   │ │  Service   │ │  Service   │
 └────────────┘ └────────────┘ └────────────┘
```

### 2.2 Architecture Principles

| Principle | Implementation |
|---|---|
| **Database per service** | Each microservice owns its data store; no shared databases. |
| **Event-driven communication** | Asynchronous events via Kafka/RabbitMQ for cross-service workflows (e.g., booking → notification). |
| **Synchronous REST** | Used only for request/response queries (e.g., gateway → service). |
| **API Gateway as single entry point** | All client traffic routes through Spring Cloud Gateway. |
| **Centralized configuration** | Spring Cloud Config Server backed by a Git repo. |
| **Service discovery** | Netflix Eureka for dynamic service registration and lookup. |
| **Resilience** | Resilience4j circuit breakers, retries, and bulkheads on all inter-service calls. |

### 2.3 Communication Patterns

```
Synchronous (REST/gRPC):
  Client → API Gateway → Target Service

Asynchronous (Event Bus):
  Booking Service  ──► booking.created  ──► Notification Service
  Booking Service  ──► booking.completed ──► Analytics Service
  Review Service   ──► review.created   ──► Shop Service (rating update)
  Shop Service     ──► shop.updated     ──► Analytics Service
```

---

## 3. Technology Stack

### 3.1 Backend

| Layer | Technology | Purpose |
|---|---|---|
| Language | Java 25 | Latest LTS features, virtual threads, pattern matching |
| Framework | Spring Boot 3.5.x | Microservice foundation |
| Cloud | Spring Cloud 2025.x | Gateway, Config, Eureka, OpenFeign |
| Security | Spring Security + OAuth2/JWT | Authentication & authorization |
| ORM | Hibernate / JPA | Object-relational mapping |
| Migrations | Flyway | Versioned database migrations |
| Build Tool | Maven (multi-module) | Build lifecycle, dependency management |

### 3.2 Frontend

| Layer | Technology | Purpose |
|---|---|---|
| Framework | React 19 | UI rendering with concurrent features |
| Language | TypeScript 5.x | Type safety |
| Build Tool | Vite 6.x | Fast dev server, HMR |
| Styling | Tailwind CSS 4.x | Utility-first CSS |
| Server State | TanStack Query v5 | Data fetching, caching, sync |
| Client State | Zustand | Minimal, scalable global state |
| Routing | React Router v7 | SPA navigation |
| Forms | React Hook Form + Zod | Validation, schema-driven forms |
| Date Handling | date-fns | Calendar and time-slot logic |

### 3.3 Databases & Messaging

| Technology | Purpose |
|---|---|
| PostgreSQL 16 | Primary relational store (one logical DB per service) |
| Redis 7 | Caching (sessions, availability slots, rate-limit counters) |
| Apache Kafka / RabbitMQ | Asynchronous event bus between services |

### 3.4 Infrastructure

| Technology | Purpose |
|---|---|
| Docker | Containerization of every service |
| Kubernetes (K8s) | Container orchestration |
| Helm | K8s package management, templated manifests |
| Terraform | Infrastructure as Code (cloud provisioning) |
| GitHub Actions | CI/CD pipelines |

### 3.5 Observability

| Technology | Purpose |
|---|---|
| OpenTelemetry | Instrumentation SDK (traces, metrics, logs) |
| Prometheus | Metrics collection & alerting |
| Grafana | Dashboards & visualization |
| Loki | Log aggregation |
| Tempo | Distributed tracing backend |

---

## 4. Feature Specifications

### 4.1 Authentication & Authorization

**Description:** Secure, role-based access control for all user types.

| Requirement | Detail |
|---|---|
| Owner registration | Email + password registration with email verification |
| Login | JWT-based; access token (15 min) + refresh token (7 days) |
| OAuth2 providers | Google, optional GitHub (for developer convenience) |
| Role enforcement | `OWNER`, `STAFF`, `CUSTOMER` roles with granular permissions |
| Password reset | Token-based password reset via email |
| Session management | Refresh token rotation; Redis-backed token blacklist |

**Flows:**
```
Registration:  Client → POST /api/v1/auth/register → Identity Service → Send verification email
Login:         Client → POST /api/v1/auth/login → Identity Service → Return {accessToken, refreshToken}
Refresh:       Client → POST /api/v1/auth/refresh → Identity Service → Rotate & return new tokens
OAuth2:        Client → /oauth2/authorize/google → Identity Service → Callback → Issue JWT
```

---

### 4.2 Owner Dashboard

**Description:** Central control panel for shop owners to manage their entire business.

**Sub-features:**

| Feature | Details |
|---|---|
| **Business Profile** | Shop name, description, address, phone, email, logo upload, social links |
| **Working Hours** | Per-day open/close times, break periods, holiday/blackout dates |
| **Service Catalog** | CRUD services with name, description, duration (min), price, category |
| **Service Categories** | Group services (e.g., "Interior", "Exterior", "Full Detail", "Paint Correction") |
| **Staff Management** | Invite staff by email, assign roles, assign services they can perform |
| **Public Page Settings** | Custom slug (`detailo.ro/s/{slug}`), theme color, toggle gallery/reviews |

---

### 4.3 Public Booking Page

**Description:** Each shop gets a unique, SEO-friendly public page accessible at `detailo.ro/s/{shop-slug}`.

**Page Sections:**

1. **Hero** — Shop name, logo, tagline, cover image
2. **Services** — Grouped by category with price, duration, description
3. **Booking Calendar** — Calendly-style appointment picker
4. **Photo Gallery** — Before/after carousel of completed jobs
5. **Reviews** — Star ratings + written reviews from verified customers
6. **Contact Info** — Address, phone, map embed, social links

**Booking Flow (Calendly-style):**
```
1. Customer selects a service (or multiple)
2. Calendar shows available dates (greyed-out unavailable)
3. Customer picks a date → available time slots appear
4. Customer picks a time slot
5. Customer enters name, email, phone, vehicle info
6. Customer confirms → booking created
7. Email confirmation sent to customer + owner/staff
```

---

### 4.4 Booking & Scheduling Engine

**Description:** The core scheduling system that manages availability, prevents double-bookings, and handles the appointment lifecycle.

**Availability Calculation:**
```
Available Slots = Working Hours
                  − Existing Bookings
                  − Break Periods
                  − Blackout Dates
                  ÷ Service Duration (with buffer time between appointments)
                  × Number of Staff Available for the Service
```

**Booking States:**

```
PENDING → CONFIRMED → IN_PROGRESS → COMPLETED
                ↓                        ↓
            CANCELLED               NO_SHOW
```

| Feature | Detail |
|---|---|
| Slot granularity | Configurable (15 / 30 / 60 min intervals) |
| Buffer time | Configurable gap between consecutive bookings |
| Staff assignment | Auto-assign or manual; round-robin by default |
| Cancellation policy | Owner-defined cutoff hours before appointment |
| Concurrent bookings | Multiple staff = multiple parallel slots |

---

### 4.5 Customer Management (Mini-CRM)

**Description:** Lightweight CRM for owners to track their customer base.

| Feature | Detail |
|---|---|
| Customer list | Searchable, sortable table of all customers for the shop |
| Customer profile | Name, email, phone, notes, total spend, visit count |
| Booking history | All past and upcoming bookings per customer |
| Vehicle profiles | Each customer can have 1+ vehicles (make, model, year, color, plate number) |
| Quick rebook | One-click rebook for a customer's last service on their saved vehicle |

---

### 4.6 Vehicle Profiles

**Description:** Saved vehicle information tied to customer accounts for faster rebooking and service tracking.

| Field | Type |
|---|---|
| Make | String (e.g., "BMW") |
| Model | String (e.g., "M3") |
| Year | Integer |
| Color | String |
| License plate | String (optional) |
| VIN | String (optional) |
| Notes | Text (e.g., "ceramic coated 2024") |

---

### 4.7 Notifications (Basic)

**Description:** Email-based notification system triggered by platform events via the message broker.

| Event | Notification | Recipient |
|---|---|---|
| `booking.created` | Booking confirmation | Customer + Owner |
| `booking.confirmed` | Appointment confirmed | Customer |
| `booking.cancelled` | Cancellation notice | Customer + Owner |
| `booking.reminder` | 24h reminder | Customer |
| `review.requested` | Post-service review request | Customer |
| `staff.invited` | Staff invitation link | Staff member |
| `auth.verify-email` | Email verification | New user |
| `auth.password-reset` | Password reset link | User |

**Implementation:** Spring Boot Mail + Thymeleaf templates. Events consumed from Kafka/RabbitMQ.

---

### 4.8 Photo Gallery

**Description:** Before/after photo showcase on the public page.

| Feature | Detail |
|---|---|
| Upload | Staff/owner uploads photos per completed booking |
| Organization | Tagged by service type, vehicle, date |
| Before/After pairing | Side-by-side or slider comparison UI |
| Display | Masonry grid on public page, lightbox on click |
| Storage | Local filesystem (dev) / S3-compatible object store (prod) |
| Limits | Max 10 MB per image, auto-resize to max 2000px width |

---

### 4.9 Reviews & Ratings

**Description:** Verified customer reviews displayed on the public booking page.

| Feature | Detail |
|---|---|
| Eligibility | Only customers with a `COMPLETED` booking can review |
| Rating | 1–5 stars |
| Review text | 10–1000 characters |
| Moderation | Owner can flag/hide inappropriate reviews (with audit trail) |
| Aggregate | Average rating + count displayed on shop profile |
| One review per booking | Prevents spam |
| Sort/filter | By date, rating, service type |

---

### 4.10 Analytics Dashboard

**Description:** Data-driven insights for shop owners.

**Metrics & Charts:**

| Metric | Visualization |
|---|---|
| Revenue (daily / weekly / monthly) | Line chart with period selector |
| Bookings count by status | Stacked bar chart |
| Top services by revenue | Horizontal bar chart |
| Top services by booking count | Horizontal bar chart |
| Customer acquisition (new vs returning) | Donut chart |
| Staff utilization rate | Per-staff progress bars |
| Average rating trend | Line chart |
| Busiest hours / days | Heatmap |
| Cancellation & no-show rate | KPI cards |

**Data Flow:** Booking, review, and shop events are consumed by the Analytics Service, which maintains pre-aggregated materialized views for fast dashboard queries.

---

### 4.11 Staff Management

**Description:** Owners can add staff members (detailers) and control their access and schedules.

| Feature | Detail |
|---|---|
| Invite by email | Owner sends invite → staff registers with `STAFF` role |
| Assign services | Each staff member is linked to the services they can perform |
| Individual schedules | Staff can have different working hours than the shop |
| Schedule view | Owner sees a combined calendar of all staff |
| Permissions | Staff can: view their schedule, update booking status, upload gallery photos |
| Deactivation | Owner can deactivate a staff member (soft delete) |

---

## 5. Microservice Breakdown

### 5.1 Service Map

| # | Service | Port | Database | Responsibilities |
|---|---|---|---|---|
| 1 | `identity-service` | 8081 | `identity_db` | Auth, JWT, OAuth2, user accounts, roles |
| 2 | `shop-service` | 8082 | `shop_db` | Shop profiles, service catalog, categories, working hours, staff, settings |
| 3 | `booking-service` | 8083 | `booking_db` | Availability engine, booking CRUD, scheduling, state machine |
| 4 | `customer-service` | 8084 | `customer_db` | Customer profiles, vehicle profiles, booking history |
| 5 | `notification-service` | 8085 | `notification_db` | Email dispatch, template rendering, delivery tracking |
| 6 | `media-service` | 8086 | `media_db` | Image upload, processing, gallery management, storage |
| 7 | `review-service` | 8087 | `review_db` | Review CRUD, rating aggregation, moderation |
| 8 | `analytics-service` | 8088 | `analytics_db` | Event consumption, metric aggregation, dashboard queries |

### 5.2 Infrastructure Services

| Service | Port | Purpose |
|---|---|---|
| `api-gateway` | 8080 | Routing, rate limiting, auth header forwarding |
| `eureka-server` | 8761 | Service discovery & registry |
| `config-server` | 8888 | Centralized configuration (Git-backed) |

### 5.3 Event Bus Topics/Queues

| Topic / Queue | Producer | Consumer(s) |
|---|---|---|
| `booking.created` | Booking Service | Notification, Analytics |
| `booking.confirmed` | Booking Service | Notification |
| `booking.cancelled` | Booking Service | Notification, Analytics |
| `booking.completed` | Booking Service | Notification, Analytics, Review (trigger review request) |
| `booking.reminder` | Booking Service (scheduled) | Notification |
| `review.created` | Review Service | Shop Service (update avg rating), Analytics |
| `user.registered` | Identity Service | Notification (welcome email) |
| `user.password-reset` | Identity Service | Notification |
| `staff.invited` | Shop Service | Notification |

---

## 6. Database Design

### 6.1 Identity DB

```sql
-- Users (all roles)
CREATE TABLE users (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email           VARCHAR(255) UNIQUE NOT NULL,
    password_hash   VARCHAR(255),
    role            VARCHAR(20) NOT NULL,  -- OWNER, STAFF, CUSTOMER
    email_verified  BOOLEAN DEFAULT FALSE,
    oauth_provider  VARCHAR(20),           -- google, github, null
    oauth_id        VARCHAR(255),
    first_name      VARCHAR(100),
    last_name       VARCHAR(100),
    avatar_url      VARCHAR(500),
    is_active       BOOLEAN DEFAULT TRUE,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Refresh tokens
CREATE TABLE refresh_tokens (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id     UUID NOT NULL REFERENCES users(id),
    token_hash  VARCHAR(255) UNIQUE NOT NULL,
    expires_at  TIMESTAMPTZ NOT NULL,
    revoked     BOOLEAN DEFAULT FALSE,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
```

### 6.2 Shop DB

```sql
-- Shop profiles
CREATE TABLE shops (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    owner_id        UUID NOT NULL,  -- references identity_service user
    name            VARCHAR(200) NOT NULL,
    slug            VARCHAR(100) UNIQUE NOT NULL,
    description     TEXT,
    phone           VARCHAR(20),
    email           VARCHAR(255),
    address         TEXT,
    latitude        DECIMAL(10, 8),
    longitude       DECIMAL(11, 8),
    logo_url        VARCHAR(500),
    cover_image_url VARCHAR(500),
    theme_color     VARCHAR(7) DEFAULT '#2563EB',
    social_links    JSONB DEFAULT '{}',
    avg_rating      DECIMAL(3, 2) DEFAULT 0.00,
    review_count    INTEGER DEFAULT 0,
    is_active       BOOLEAN DEFAULT TRUE,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Service categories
CREATE TABLE service_categories (
    id       UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    shop_id  UUID NOT NULL REFERENCES shops(id),
    name     VARCHAR(100) NOT NULL,
    sort_order INTEGER DEFAULT 0
);

-- Detailing services
CREATE TABLE services (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    shop_id         UUID NOT NULL REFERENCES shops(id),
    category_id     UUID REFERENCES service_categories(id),
    name            VARCHAR(200) NOT NULL,
    description     TEXT,
    duration_minutes INTEGER NOT NULL,
    price_cents     INTEGER NOT NULL,
    currency        VARCHAR(3) DEFAULT 'RON',
    is_active       BOOLEAN DEFAULT TRUE,
    sort_order      INTEGER DEFAULT 0,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Working hours
CREATE TABLE working_hours (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    shop_id     UUID NOT NULL REFERENCES shops(id),
    day_of_week INTEGER NOT NULL,  -- 0=Monday, 6=Sunday
    open_time   TIME NOT NULL,
    close_time  TIME NOT NULL,
    is_closed   BOOLEAN DEFAULT FALSE
);

-- Break periods within a day
CREATE TABLE break_periods (
    id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    working_hours_id  UUID NOT NULL REFERENCES working_hours(id),
    start_time        TIME NOT NULL,
    end_time          TIME NOT NULL
);

-- Blackout / holiday dates
CREATE TABLE blackout_dates (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    shop_id    UUID NOT NULL REFERENCES shops(id),
    date       DATE NOT NULL,
    reason     VARCHAR(200)
);

-- Staff members
CREATE TABLE staff_members (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    shop_id     UUID NOT NULL REFERENCES shops(id),
    user_id     UUID,  -- null until invite is accepted
    email       VARCHAR(255) NOT NULL,
    first_name  VARCHAR(100),
    last_name   VARCHAR(100),
    invite_token VARCHAR(255),
    invite_status VARCHAR(20) DEFAULT 'PENDING',  -- PENDING, ACCEPTED
    is_active   BOOLEAN DEFAULT TRUE,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Staff ↔ Service mapping
CREATE TABLE staff_services (
    staff_id   UUID NOT NULL REFERENCES staff_members(id),
    service_id UUID NOT NULL REFERENCES services(id),
    PRIMARY KEY (staff_id, service_id)
);

-- Staff individual working hours (overrides shop hours)
CREATE TABLE staff_working_hours (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    staff_id    UUID NOT NULL REFERENCES staff_members(id),
    day_of_week INTEGER NOT NULL,
    open_time   TIME NOT NULL,
    close_time  TIME NOT NULL,
    is_off      BOOLEAN DEFAULT FALSE
);
```

### 6.3 Booking DB

```sql
CREATE TABLE bookings (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    shop_id         UUID NOT NULL,
    customer_id     UUID NOT NULL,
    staff_id        UUID,              -- assigned staff
    vehicle_id      UUID,              -- customer's vehicle
    status          VARCHAR(20) NOT NULL DEFAULT 'PENDING',
    booking_date    DATE NOT NULL,
    start_time      TIME NOT NULL,
    end_time        TIME NOT NULL,
    total_price_cents INTEGER NOT NULL,
    currency        VARCHAR(3) DEFAULT 'RON',
    customer_notes  TEXT,
    cancellation_reason TEXT,
    cancelled_by    VARCHAR(20),       -- CUSTOMER, OWNER
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Many-to-many: bookings ↔ services
CREATE TABLE booking_services (
    booking_id UUID NOT NULL REFERENCES bookings(id),
    service_id UUID NOT NULL,
    price_cents INTEGER NOT NULL,      -- snapshot at booking time
    duration_minutes INTEGER NOT NULL, -- snapshot at booking time
    PRIMARY KEY (booking_id, service_id)
);

-- Slot configuration per shop
CREATE TABLE slot_configs (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    shop_id             UUID NOT NULL UNIQUE,
    slot_interval_minutes  INTEGER NOT NULL DEFAULT 30,
    buffer_minutes      INTEGER NOT NULL DEFAULT 15,
    max_advance_days    INTEGER NOT NULL DEFAULT 60,
    cancellation_hours  INTEGER NOT NULL DEFAULT 24
);
```

### 6.4 Customer DB

```sql
CREATE TABLE customers (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    shop_id     UUID NOT NULL,
    user_id     UUID,                  -- link to identity_service (nullable for walk-ins)
    first_name  VARCHAR(100) NOT NULL,
    last_name   VARCHAR(100),
    email       VARCHAR(255),
    phone       VARCHAR(20),
    notes       TEXT,
    total_spend_cents INTEGER DEFAULT 0,
    visit_count INTEGER DEFAULT 0,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(shop_id, email)
);

CREATE TABLE vehicles (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    customer_id  UUID NOT NULL REFERENCES customers(id),
    make         VARCHAR(50) NOT NULL,
    model        VARCHAR(50) NOT NULL,
    year         INTEGER,
    color        VARCHAR(30),
    license_plate VARCHAR(20),
    vin          VARCHAR(17),
    notes        TEXT,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
```

### 6.5 Media DB

```sql
CREATE TABLE gallery_items (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    shop_id       UUID NOT NULL,
    booking_id    UUID,
    uploaded_by   UUID NOT NULL,       -- staff or owner user_id
    type          VARCHAR(10) NOT NULL, -- BEFORE, AFTER
    pair_id       UUID,                -- links before/after pairs
    image_url     VARCHAR(500) NOT NULL,
    thumbnail_url VARCHAR(500),
    service_tag   VARCHAR(100),        -- e.g., "Paint Correction"
    vehicle_info  VARCHAR(200),        -- e.g., "BMW M3 2022"
    is_visible    BOOLEAN DEFAULT TRUE,
    sort_order    INTEGER DEFAULT 0,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
```

### 6.6 Review DB

```sql
CREATE TABLE reviews (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    shop_id      UUID NOT NULL,
    booking_id   UUID NOT NULL UNIQUE, -- one review per booking
    customer_id  UUID NOT NULL,
    rating       INTEGER NOT NULL CHECK (rating BETWEEN 1 AND 5),
    comment      TEXT CHECK (char_length(comment) BETWEEN 10 AND 1000),
    is_visible   BOOLEAN DEFAULT TRUE,
    flagged      BOOLEAN DEFAULT FALSE,
    flag_reason  TEXT,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
```

### 6.7 Notification DB

```sql
CREATE TABLE notifications (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    recipient_email VARCHAR(255) NOT NULL,
    template_name VARCHAR(50) NOT NULL,
    subject       VARCHAR(255),
    payload       JSONB NOT NULL,
    status        VARCHAR(20) DEFAULT 'PENDING', -- PENDING, SENT, FAILED
    error_message TEXT,
    sent_at       TIMESTAMPTZ,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
```

### 6.8 Analytics DB

```sql
-- Pre-aggregated daily metrics
CREATE TABLE daily_metrics (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    shop_id         UUID NOT NULL,
    metric_date     DATE NOT NULL,
    total_bookings  INTEGER DEFAULT 0,
    completed_bookings INTEGER DEFAULT 0,
    cancelled_bookings INTEGER DEFAULT 0,
    no_show_count   INTEGER DEFAULT 0,
    revenue_cents   INTEGER DEFAULT 0,
    new_customers   INTEGER DEFAULT 0,
    returning_customers INTEGER DEFAULT 0,
    avg_rating      DECIMAL(3,2),
    UNIQUE(shop_id, metric_date)
);

-- Per-service metrics
CREATE TABLE service_metrics (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    shop_id         UUID NOT NULL,
    service_id      UUID NOT NULL,
    metric_date     DATE NOT NULL,
    booking_count   INTEGER DEFAULT 0,
    revenue_cents   INTEGER DEFAULT 0,
    UNIQUE(shop_id, service_id, metric_date)
);

-- Hourly booking distribution (for heatmap)
CREATE TABLE hourly_distribution (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    shop_id     UUID NOT NULL,
    day_of_week INTEGER NOT NULL,
    hour        INTEGER NOT NULL,
    booking_count INTEGER DEFAULT 0,
    UNIQUE(shop_id, day_of_week, hour)
);
```

---

## 7. API Design

All APIs follow REST conventions with the base path `/api/v1`. Authentication is via `Authorization: Bearer <JWT>` header.

### 7.1 Identity Service — `/api/v1/auth`

```
POST   /register                  Register new user (owner or customer)
POST   /login                     Authenticate, return JWT pair
POST   /refresh                   Refresh access token
POST   /logout                    Revoke refresh token
POST   /forgot-password           Send password reset email
POST   /reset-password            Reset password with token
GET    /me                        Get current user profile
PATCH  /me                        Update current user profile
POST   /oauth2/google             Google OAuth2 flow
GET    /verify-email?token=...    Verify email address
```

### 7.2 Shop Service — `/api/v1/shops`

```
POST   /                          Create shop (owner only)
GET    /{shopId}                   Get shop details
PATCH  /{shopId}                   Update shop profile
GET    /by-slug/{slug}             Get shop by public slug (public)

# Services
GET    /{shopId}/services                List services
POST   /{shopId}/services                Create service
PATCH  /{shopId}/services/{serviceId}    Update service
DELETE /{shopId}/services/{serviceId}    Deactivate service

# Categories
GET    /{shopId}/categories              List categories
POST   /{shopId}/categories              Create category
PATCH  /{shopId}/categories/{id}         Update category
DELETE /{shopId}/categories/{id}         Delete category

# Working Hours
GET    /{shopId}/working-hours           Get working hours
PUT    /{shopId}/working-hours           Set working hours (bulk)
GET    /{shopId}/blackout-dates          List blackout dates
POST   /{shopId}/blackout-dates          Add blackout date
DELETE /{shopId}/blackout-dates/{id}     Remove blackout date

# Staff
GET    /{shopId}/staff                   List staff
POST   /{shopId}/staff                   Invite staff member
PATCH  /{shopId}/staff/{staffId}         Update staff
DELETE /{shopId}/staff/{staffId}         Deactivate staff
PUT    /{shopId}/staff/{staffId}/services Assign services to staff
GET    /{shopId}/staff/{staffId}/hours   Get staff working hours
PUT    /{shopId}/staff/{staffId}/hours   Set staff working hours
```

### 7.3 Booking Service — `/api/v1/bookings`

```
POST   /                                 Create booking
GET    /{bookingId}                       Get booking details
PATCH  /{bookingId}/status               Update booking status
PATCH  /{bookingId}/cancel               Cancel booking

# Availability (public)
GET    /availability?shopId=&date=&serviceIds=   Get available time slots

# Shop's bookings (owner/staff)
GET    /shop/{shopId}?status=&date=&staffId=     List bookings with filters
GET    /shop/{shopId}/calendar?from=&to=         Calendar view (date range)
```

### 7.4 Customer Service — `/api/v1/customers`

```
GET    /shop/{shopId}                     List customers for shop
GET    /{customerId}                      Get customer details
PATCH  /{customerId}                      Update customer
GET    /{customerId}/bookings             Get customer booking history
GET    /{customerId}/vehicles             List vehicles
POST   /{customerId}/vehicles             Add vehicle
PATCH  /{customerId}/vehicles/{id}        Update vehicle
DELETE /{customerId}/vehicles/{id}        Delete vehicle
```

### 7.5 Media Service — `/api/v1/media`

```
POST   /upload                           Upload image(s)
GET    /shop/{shopId}/gallery             Get gallery (public)
POST   /shop/{shopId}/gallery             Create gallery item (with uploaded image ref)
PATCH  /gallery/{itemId}                  Update gallery item
DELETE /gallery/{itemId}                  Delete gallery item
```

### 7.6 Review Service — `/api/v1/reviews`

```
POST   /                                 Submit review
GET    /shop/{shopId}?sort=&rating=       List reviews (public)
GET    /{reviewId}                        Get single review
PATCH  /{reviewId}/flag                   Flag/unflag review (owner)
PATCH  /{reviewId}/visibility             Toggle visibility (owner)
```

### 7.7 Analytics Service — `/api/v1/analytics`

```
GET    /shop/{shopId}/dashboard           Dashboard summary (KPI cards)
GET    /shop/{shopId}/revenue?from=&to=&granularity=   Revenue chart data
GET    /shop/{shopId}/bookings?from=&to=               Booking stats
GET    /shop/{shopId}/top-services?from=&to=&by=       Top services
GET    /shop/{shopId}/customers?from=&to=               Customer metrics
GET    /shop/{shopId}/staff-utilization?from=&to=       Staff utilization
GET    /shop/{shopId}/heatmap                           Hourly booking heatmap
GET    /shop/{shopId}/ratings?from=&to=                 Rating trend
```

---

## 8. Frontend Architecture

### 8.1 Project Structure

```
frontend/
├── public/
├── src/
│   ├── api/              # API client, axios instance, endpoint definitions
│   │   ├── client.ts
│   │   ├── auth.api.ts
│   │   ├── shop.api.ts
│   │   ├── booking.api.ts
│   │   └── ...
│   ├── components/        # Reusable UI components
│   │   ├── ui/            # Primitives (Button, Input, Card, Modal, etc.)
│   │   ├── layout/        # Shell, Sidebar, Navbar, Footer
│   │   ├── calendar/      # Booking calendar components
│   │   ├── gallery/       # Photo gallery & lightbox
│   │   └── charts/        # Analytics chart wrappers
│   ├── features/          # Feature-based modules
│   │   ├── auth/          # Login, Register, ForgotPassword pages + hooks
│   │   ├── dashboard/     # Owner dashboard pages
│   │   ├── shop/          # Shop profile management
│   │   ├── services/      # Service catalog management
│   │   ├── staff/         # Staff management
│   │   ├── bookings/      # Booking management (owner view)
│   │   ├── customers/     # Customer CRM
│   │   ├── analytics/     # Analytics dashboard
│   │   └── public-page/   # Public booking page (customer-facing)
│   ├── hooks/             # Shared custom hooks
│   ├── stores/            # Zustand stores
│   │   ├── authStore.ts
│   │   └── uiStore.ts
│   ├── types/             # TypeScript type definitions
│   ├── utils/             # Helper functions
│   ├── lib/               # Third-party library wrappers
│   ├── styles/            # Global styles, Tailwind config
│   ├── App.tsx
│   ├── main.tsx
│   └── router.tsx         # Route definitions
├── index.html
├── vite.config.ts
├── tailwind.config.ts
├── tsconfig.json
└── package.json
```

### 8.2 Route Map

| Path | Page | Access |
|---|---|---|
| `/login` | Login | Public |
| `/register` | Registration | Public |
| `/forgot-password` | Password reset | Public |
| `/dashboard` | Dashboard overview | Owner |
| `/dashboard/shop` | Shop profile editor | Owner |
| `/dashboard/services` | Service management | Owner |
| `/dashboard/staff` | Staff management | Owner |
| `/dashboard/bookings` | Booking management | Owner, Staff |
| `/dashboard/customers` | Customer CRM | Owner |
| `/dashboard/gallery` | Gallery management | Owner, Staff |
| `/dashboard/analytics` | Analytics | Owner |
| `/dashboard/settings` | Account settings | Owner |
| `/s/{slug}` | Public booking page | Public |
| `/s/{slug}/book` | Booking flow | Public |

### 8.3 State Management Strategy

| State Type | Tool | Examples |
|---|---|---|
| Server state | TanStack Query | Shop data, bookings, services, customers |
| Auth state | Zustand + persist | User, tokens, role |
| UI state | Zustand | Sidebar open, active modal, theme |
| Form state | React Hook Form | Service editor, booking form |

### 8.4 Key UI Patterns

- **Optimistic updates** — TanStack Query mutations with `onMutate` for instant feedback.
- **Infinite scroll** — For customer lists, booking history, reviews.
- **Debounced search** — For customer search, service search.
- **Skeleton loading** — For every data-dependent component.
- **Toast notifications** — For success/error feedback.
- **Responsive design** — Mobile-first; dashboard collapses sidebar on small screens.
- **Dark mode** — Toggle via Zustand `uiStore`, applied via Tailwind `dark:` classes.

---

## 9. Infrastructure & DevOps

### 9.1 Docker

Each service gets a multi-stage `Dockerfile`:

```dockerfile
# Build stage
FROM eclipse-temurin:25-jdk AS build
WORKDIR /app
COPY pom.xml .
COPY src ./src
RUN ./mvnw package -DskipTests

# Runtime stage
FROM eclipse-temurin:25-jre
COPY --from=build /app/target/*.jar app.jar
EXPOSE 8080
ENTRYPOINT ["java", "-jar", "app.jar"]
```

### 9.2 Docker Compose (Local Development)

Full local stack with all services, databases, Redis, Kafka, and observability:

```
docker-compose.yml
├── eureka-server       :8761
├── config-server       :8888
├── api-gateway         :8080
├── identity-service    :8081
├── shop-service        :8082
├── booking-service     :8083
├── customer-service    :8084
├── notification-service:8085
├── media-service       :8086
├── review-service      :8087
├── analytics-service   :8088
├── postgres            :5432
├── redis               :6379
├── kafka + zookeeper   :9092
├── prometheus          :9090
├── grafana             :3000
├── loki                :3100
├── tempo               :3200
└── frontend (Vite)     :5173
```

### 9.3 Kubernetes

```
k8s/
├── namespaces/
│   └── detailo-namespace.yaml
├── infrastructure/
│   ├── postgres-statefulset.yaml
│   ├── redis-deployment.yaml
│   ├── kafka-statefulset.yaml
│   └── configmaps/
├── services/
│   ├── identity-service/
│   │   ├── deployment.yaml
│   │   ├── service.yaml
│   │   ├── hpa.yaml              # Horizontal Pod Autoscaler
│   │   └── configmap.yaml
│   ├── shop-service/
│   ├── booking-service/
│   └── ... (same pattern per service)
├── ingress/
│   └── ingress.yaml              # NGINX Ingress Controller
└── monitoring/
    ├── prometheus/
    ├── grafana/
    └── loki/
```

### 9.4 Helm Charts

```
helm/
├── Chart.yaml
├── values.yaml
├── values-staging.yaml
├── values-production.yaml
└── templates/
    ├── _helpers.tpl
    ├── deployment.yaml    # Templated for all services
    ├── service.yaml
    ├── hpa.yaml
    ├── ingress.yaml
    └── configmap.yaml
```

### 9.5 Terraform

```
terraform/
├── main.tf
├── variables.tf
├── outputs.tf
├── modules/
│   ├── networking/         # VPC, subnets, security groups
│   ├── kubernetes/         # EKS / GKE cluster
│   ├── database/           # RDS PostgreSQL
│   ├── cache/              # ElastiCache Redis
│   ├── messaging/          # MSK / CloudAMQP
│   └── storage/            # S3 bucket for media
└── environments/
    ├── staging/
    │   └── terraform.tfvars
    └── production/
        └── terraform.tfvars
```

### 9.6 CI/CD — GitHub Actions

```yaml
# .github/workflows/ci.yml — Triggered on every PR
jobs:
  lint-and-test:
    - Checkstyle / SpotBugs (Java)
    - ESLint / TypeScript check (Frontend)
    - Unit tests (JUnit 5 + Mockito)
    - Integration tests (Testcontainers)
    - Frontend tests (Vitest + Testing Library)
    - Code coverage report (JaCoCo / Codecov)

# .github/workflows/cd.yml — Triggered on merge to main
jobs:
  build-and-push:
    - Build Docker images
    - Push to GitHub Container Registry (GHCR)
    - Tag with commit SHA + semver

  deploy-staging:
    - Helm upgrade to staging namespace
    - Run smoke tests
    - Notify on Slack / Discord

  deploy-production:
    - Manual approval gate
    - Helm upgrade to production namespace
    - Health check validation
```

---

## 10. Observability

### 10.1 Stack

```
Application → OpenTelemetry SDK
         ├── Traces  → Tempo     → Grafana
         ├── Metrics → Prometheus → Grafana
         └── Logs    → Loki      → Grafana
```

### 10.2 Key Dashboards (Grafana)

| Dashboard | Panels |
|---|---|
| **Service Health** | Request rate, error rate, latency (RED metrics) per service |
| **JVM Metrics** | Heap usage, GC pauses, thread count, virtual threads |
| **Database** | Connection pool, query latency, active connections |
| **Booking Pipeline** | Bookings/min, status distribution, processing time |
| **Kafka/RabbitMQ** | Consumer lag, message throughput, dead-letter queue |

### 10.3 Distributed Tracing

Every request gets a `traceId` propagated through:
```
Client → API Gateway → Service A → Kafka → Service B
  └── All spans visible in Grafana Tempo with service map
```

### 10.4 Alerting Rules (Prometheus)

| Alert | Condition |
|---|---|
| High error rate | 5xx rate > 5% over 5 min |
| Service down | Health endpoint unresponsive for 2 min |
| High latency | p99 latency > 2s for 5 min |
| Database connection pool exhausted | Available connections < 2 |
| Kafka consumer lag | Lag > 1000 messages for 10 min |

---

## 11. Security

### 11.1 Authentication & Token Flow

```
┌────────┐         ┌───────────┐         ┌──────────────┐
│ Client │──login──▶│ API GW    │──route──▶│ Identity Svc │
│        │◀─JWT────│           │◀─JWT─────│              │
└────┬───┘         └─────┬─────┘         └──────────────┘
     │                   │
     │ Bearer token      │ Validate JWT (public key)
     │ on every request  │ Extract userId, role
     │                   │ Forward as X-User-Id, X-User-Role headers
     ▼                   ▼
┌──────────────────────────────┐
│       Target Service         │
│  Reads headers, enforces     │
│  authorization               │
└──────────────────────────────┘
```

### 11.2 Security Measures

| Area | Measure |
|---|---|
| Passwords | BCrypt hashing (strength 12) |
| JWT | RS256 asymmetric signing; short-lived access tokens |
| CORS | Strict origin allowlist |
| Rate limiting | Per-IP, per-user via API Gateway + Redis |
| Input validation | Jakarta Bean Validation + Zod (frontend) |
| SQL injection | Parameterized queries via JPA |
| XSS | React auto-escaping + CSP headers |
| CSRF | Not applicable (JWT, no cookies) |
| File uploads | Type validation, size limits, antivirus scan |
| Secrets | Never in code; injected via env vars / K8s Secrets |
| HTTPS | TLS termination at ingress |
| Dependencies | Dependabot + Snyk for vulnerability scanning |

---

## 12. Development Phases

### Phase 1 — Foundation & Infrastructure (Weeks 1–2)

| Task | Details |
|---|---|
| Project scaffolding | Monorepo structure, parent POM, shared libraries |
| Config Server + Eureka | Centralized config with Git-backed repo, service discovery |
| API Gateway | Spring Cloud Gateway with route definitions |
| Docker Compose | Full local dev environment |
| CI pipeline | GitHub Actions for lint, test, build |
| Frontend init | Vite + React + TypeScript + Tailwind + Router |
| Design system | Shared UI components (Button, Input, Card, Modal, Table) |

### Phase 2 — Identity & Shop (Weeks 3–5)

| Task | Details |
|---|---|
| Identity Service | User registration, login, JWT, OAuth2 (Google), email verification |
| Shop Service | Shop CRUD, service catalog, categories, working hours |
| Staff management | Invite flow, service assignment, individual hours |
| Frontend auth | Login, register, forgot-password pages |
| Dashboard shell | Sidebar navigation, layout, protected routes |
| Shop profile UI | Business info form, working hours editor |
| Service management UI | CRUD interface with drag-and-drop reorder |

### Phase 3 — Booking Engine (Weeks 6–8)

| Task | Details |
|---|---|
| Booking Service | Availability engine, booking CRUD, state machine |
| Customer Service | Customer profiles, vehicle CRUD |
| Redis caching | Cache availability slots, invalidate on booking changes |
| Kafka/RabbitMQ setup | Event bus, topic creation, consumer groups |
| Public booking page | Shop page with service list, calendar, booking flow |
| Booking calendar UI | Calendly-style date picker, time-slot grid |
| Owner booking view | Calendar view, list view, filters, status updates |
| Customer CRM UI | Customer table, profile view, vehicle management |

### Phase 4 — Engagement Features (Weeks 9–11)

| Task | Details |
|---|---|
| Notification Service | Kafka consumer, email templates (Thymeleaf), SMTP integration |
| Media Service | Image upload, thumbnail generation, gallery CRUD |
| Review Service | Review CRUD, rating aggregation, moderation |
| Gallery UI | Upload flow, before/after pairing, public masonry grid |
| Reviews UI | Review list, star ratings, owner moderation panel |
| Notification templates | Booking confirmation, reminder, review request emails |

### Phase 5 — Analytics & Polish (Weeks 12–14)

| Task | Details |
|---|---|
| Analytics Service | Event consumer, daily aggregation jobs, dashboard queries |
| Analytics UI | Charts (Recharts/Chart.js), KPI cards, date range picker |
| Staff calendar | Combined multi-staff calendar view |
| Dark mode | Full theme support across dashboard |
| Responsive design | Mobile optimization for public page + dashboard |
| Performance | Query optimization, lazy loading, code splitting |

### Phase 6 — Production Readiness (Weeks 15–17)

| Task | Details |
|---|---|
| Kubernetes manifests | Deployments, services, HPAs, configmaps |
| Helm charts | Templated, environment-specific values |
| Terraform | Cloud infrastructure provisioning |
| Observability stack | OpenTelemetry, Prometheus, Grafana, Loki, Tempo |
| Security hardening | Rate limiting, CORS, CSP, dependency audit |
| Load testing | k6 / Gatling scripts for booking flow |
| Documentation | API docs (SpringDoc/OpenAPI), README, ADRs |
| CD pipeline | Staging + production deploy with approval gates |

---

## 13. Testing Strategy

### 13.1 Test Pyramid

```
         ╱  E2E Tests  ╲         ← Playwright (critical flows)
        ╱───────────────╲
       ╱ Integration Tests╲      ← Testcontainers (DB, Kafka, Redis)
      ╱─────────────────────╲
     ╱     Unit Tests         ╲  ← JUnit 5 + Mockito (business logic)
    ╱───────────────────────────╲
   ╱    Static Analysis          ╲ ← Checkstyle, SpotBugs, ESLint, TypeScript
  ╱───────────────────────────────╲
```

### 13.2 Backend Testing

| Layer | Tool | Target |
|---|---|---|
| Unit | JUnit 5 + Mockito | Service classes, utility functions, mappers |
| Integration | Testcontainers | Repository tests with real PostgreSQL, Redis, Kafka |
| API | MockMvc / WebTestClient | Controller endpoints, request/response validation |
| Contract | Spring Cloud Contract | Consumer-driven contracts between services |

### 13.3 Frontend Testing

| Layer | Tool | Target |
|---|---|---|
| Unit | Vitest | Utility functions, hooks, store logic |
| Component | Testing Library | Component rendering, user interactions |
| E2E | Playwright | Critical user flows (register, book, manage) |

### 13.4 Coverage Targets

| Area | Target |
|---|---|
| Backend service layer | ≥ 80% |
| Backend controllers | ≥ 70% |
| Frontend components | ≥ 60% |
| E2E critical paths | 100% of happy paths |

---

## Appendix A — Monorepo Structure

```
detailo/
├── .github/
│   └── workflows/
│       ├── ci.yml
│       └── cd.yml
├── config-repo/                    # Git-backed config for Config Server
│   ├── identity-service.yml
│   ├── shop-service.yml
│   ├── booking-service.yml
│   └── ...
├── eureka-server/                  # Netflix Eureka
├── config-server/                  # Spring Cloud Config
├── api-gateway/                    # Spring Cloud Gateway
├── identity-service/               # Auth & user management
├── shop-service/                   # Shop, services, staff
├── booking-service/                # Scheduling engine
├── customer-service/               # CRM & vehicles
├── notification-service/           # Email notifications
├── media-service/                  # Photo gallery
├── review-service/                 # Reviews & ratings
├── analytics-service/              # Metrics & reporting
├── shared-lib/                     # Shared DTOs, events, utils
├── frontend/                       # React SPA
├── k8s/                            # Kubernetes manifests
├── helm/                           # Helm charts
├── terraform/                      # IaC
├── docker-compose.yml
├── docker-compose.dev.yml
├── pom.xml                         # Parent POM
├── development-plan.md
├── CONTRIBUTING.md
├── LICENSE
└── README.md
```

---

## Appendix B — Shared Library (`shared-lib`)

Common code extracted into a Maven module used by all services:

```
shared-lib/
├── src/main/java/com/detailo/shared/
│   ├── dto/                 # Cross-service DTOs (UserInfo, ShopSummary)
│   ├── event/               # Event classes (BookingCreatedEvent, ReviewCreatedEvent)
│   ├── exception/           # Global exception types (ResourceNotFoundException, etc.)
│   ├── security/            # JWT utility, SecurityContext helpers
│   └── response/            # Standard API response wrapper (ApiResponse<T>)
└── pom.xml
```

---

## Appendix C — Environment Variables

| Variable | Service | Description |
|---|---|---|
| `JWT_PRIVATE_KEY` | Identity | RSA private key for signing JWTs |
| `JWT_PUBLIC_KEY` | API Gateway, all services | RSA public key for verifying JWTs |
| `DB_URL` | All services | PostgreSQL JDBC URL |
| `DB_USERNAME` / `DB_PASSWORD` | All services | Database credentials |
| `REDIS_HOST` / `REDIS_PORT` | Booking, Identity | Redis connection |
| `KAFKA_BOOTSTRAP_SERVERS` | All producers/consumers | Kafka broker address |
| `SMTP_HOST` / `SMTP_PORT` | Notification | Mail server |
| `SMTP_USERNAME` / `SMTP_PASSWORD` | Notification | Mail credentials |
| `MEDIA_STORAGE_PATH` | Media | Local file path (dev) |
| `S3_BUCKET` / `S3_REGION` | Media | S3 storage (prod) |
| `GOOGLE_CLIENT_ID` / `GOOGLE_CLIENT_SECRET` | Identity | OAuth2 provider |
| `CONFIG_SERVER_URI` | All services | Config Server URL |
| `EUREKA_URI` | All services | Eureka Server URL |
