//! Binary protocol module (Chat & DM).
//!
//! 共通のフレーム定義・エンコード/デコード・エラー型は `base` にあり、
//! メッセージ種別（Chat / DM）ごとのコンストラクタとテストは
//! `chat` / `dm` に分割されている。

pub mod base;
pub mod chat;
pub mod dm;

pub use base::*;
