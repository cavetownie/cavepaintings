---
title: "{{ replace .Name "-" " " | title }}"
date: {{ .Date }}
author: "{{ .Site.Params.author | default "Anonymous" }}"
tags: []
categories: []
summary: "Enter a brief summary of your post here"
draft: true
---

# {{ replace .Name "-" " " | title }}

Start writing your retro blog post here! 

Remember to:
- Add relevant tags
- Write a compelling summary
- Set draft to false when ready to publish

Welcome to the nostalgic world of Windows 95 blogging! 🖥️
