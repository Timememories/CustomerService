# Intelligent Customer Service System: Flask-SQLAlchemy-Jinja2 Platform

### [README.md](README.md) (中英双语版，更新项目名称为Intelligent customer service system)

# Intelligent customer service system - 智能客户服务系统

# Intelligent customer service system - Intelligent Customer Service System

一个基于 Flask + SQLAlchemy + Jinja2 构建的智能客户服务管理平台，提供用户认证、智能客服会话管理、权限控制等核心功能，支持多角色协作与高效客户服务流程。  

An intelligent customer service management platform built with Flask + SQLAlchemy + Jinja2, providing core functions such as user authentication, intelligent customer service session management, and permission control, supporting multi-role collaboration and efficient customer service processes.

## 项目概述 | Project Overview

该系统旨在为企业提供智能化、标准化的客户服务解决方案，通过分层权限管理（管理员/客服人员/普通用户）实现服务流程的规范化与高效化。系统采用经典的后端渲染架构，结合轻量化前端交互设计，兼顾智能服务能力与管理效率，适配企业级客户服务场景的多样化需求。  

This system aims to provide intelligent and standardized customer service solutions for enterprises, realizing the standardization and efficiency of service processes through hierarchical permission management (Administrator/Customer Service Agent/Regular User). It adopts a classic server-side rendering architecture combined with lightweight front-end interaction design, balancing intelligent service capabilities and management efficiency to adapt to the diverse needs of enterprise-level customer service scenarios.

## 技术栈 | Technology Stack

### 核心框架 | Core Framework

- **后端 | Backend**: Python + Flask 4.2 (Web框架 | Web Framework)

- **ORM**: SQLAlchemy (数据库交互 | Database Interaction)

- **模板引擎 | Template Engine**: Jinja2 (动态页面渲染 | Dynamic Page Rendering)

- **数据库 | Database**: SQLite (轻量嵌入式数据库，便于部署 | Lightweight embedded database for easy deployment)

- **前端 | Frontend**:

  - 样式框架 | Styling Framework: Bootstrap 5.3 + 自定义CSS变量 | Custom CSS Variables

  - 交互 | Interaction: 原生JavaScript + Font Awesome图标 | Native JavaScript + Font Awesome Icons

  - 响应式设计 | Responsive Design: 适配PC与移动端 | Compatible with PC and Mobile Devices

## 功能模块 | Functional Modules

### 1. 用户认证与管理 | User Authentication & Management

- 账号注册/登录/密码重置（支持密码强度检测与验证）| Account registration/login/password reset (supports password strength detection and verification)

- 基于角色的权限控制（RBAC）| Role-Based Access Control (RBAC):

  - 管理员 | Administrator: 用户管理、权限配置、系统参数设置 | User management, permission configuration, system parameter setting

  - 客服人员 | Customer Service Agent: 智能会话处理、客户沟通、服务记录维护 | Intelligent session processing, customer communication, service record maintenance

  - 普通用户 | Regular User: 发起智能咨询、查看服务记录、提交服务评价 | Initiate intelligent consultations, view service records, submit service evaluations

### 2. 智能客服会话管理 | Intelligent Customer Service Session Management

- 实时会话列表展示（包含会话ID、用户信息、创建时间、智能标签）| Real-time session list display (including session ID, user info, creation time, intelligent tags)

- 会话状态跟踪（待处理/处理中/已结束/已转接）| Session status tracking (Pending/In Progress/Completed/Transferred)

- 历史会话记录查询与追溯（支持关键词智能检索）| Historical session record query and traceability (support intelligent keyword retrieval)

- 智能回复模板调用（提升客服响应效率）| Intelligent reply template invocation (improve customer service response efficiency)

### 3. 系统管理与数据分析 | System Management & Data Analysis

- 仪表盘数据可视化（客服工作量、响应效率、用户满意度等核心指标）| Dashboard data visualization (core metrics such as agent workload, response efficiency, user satisfaction)

- 用户角色与权限精细化配置 | Refined configuration of user roles and permissions

- 操作日志记录与审计（支持按操作类型/时间/用户检索）| Operation log recording and auditing (support retrieval by operation type/time/user)

- 服务数据统计与导出（按日/周/月生成报表）| Service data statistics and export (generate reports by day/week/month)

## 项目结构 | Project Structure

```Plain Text

```

## 部署指南 | Deployment Guide

### 环境要求 | Environment Requirements

- Python 3.9+

- 依赖管理 | Dependency Management: pip

### 部署步骤 | Deployment Steps

1. **克隆仓库 | Clone the Repository**

   ```Bash
   
   ```

2. **创建虚拟环境 | Create a Virtual Environment**

   ```Bash
   
   ```

3. **安装依赖 | Install Dependencies**

   ```Bash
   
   ```

4. **初始化数据库 | Initialize the Database**

   ```Bash
   
   ```

5. **启动应用 | Start the Application**

   ```Bash
   
   ```

## 界面设计特点 | UI Design Features

- **品牌一致性 | Brand Consistency**: 采用科技感淡紫色（#9F7AEA）为主色调，配合浅蓝渐变背景，契合智能客服的产品定位 | Uses tech-style light purple (#9F7AEA) as the main color, combined with light blue gradient backgrounds, aligning with the product positioning of intelligent customer service

- **交互优化 | Interaction Optimization**: 密码显隐切换、表单实时验证、智能回复联想、提交状态反馈等细节提升用户体验 | Password show/hide toggle, real-time form validation, intelligent reply association, submission status feedback and other details to improve user experience

- **响应式布局 | Responsive Layout**: 适配桌面端、平板与移动端，确保多终端使用一致性 | Adapt to desktop, tablet and mobile terminals to ensure consistent use across multiple devices

- **错误处理 | Error Handling**: 友好的404/500错误页面，提供智能问题排查指引与人工支持入口 | User-friendly 404/500 error pages with intelligent troubleshooting guidelines and manual support entrances

## 扩展建议 | Extension Suggestions

1. 集成WebSocket实现实时智能聊天与消息推送 | Integrate WebSocket to implement real-time intelligent chat and message push

2. 接入LLM大语言模型，实现智能意图识别与自动回复 | Connect LLM (Large Language Model) to implement intelligent intent recognition and automatic replies

3. 对接企业邮箱/短信服务，实现服务通知与密码重置提醒 | Connect enterprise email/SMS services to implement service notifications and password reset reminders

4. 迁移至PostgreSQL/MySQL，支持高并发与海量会话数据存储 | Migrate to PostgreSQL/MySQL to support high concurrency and massive session data storage

5. 增加多语言支持，适配跨境企业客户服务场景 | Add multi-language support to adapt to cross-border enterprise customer service scenarios

如需进一步开发或定制功能，请参考代码注释与Flask官方文档进行扩展。  

For further development or custom function customization, please refer to the code comments and Flask official documentation for extension.

> （注：文档部分内容可能由 AI 生成）