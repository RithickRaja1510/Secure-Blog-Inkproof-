'use strict';
/**
 * Central authorization policy. Every route consults these functions; nothing is decided
 * from client-supplied data (hidden fields, ids in the URL are only used to LOOK UP records).
 *
 *                      anonymous   user (non-owner)   owner        admin
 *  read published        yes          yes              yes          yes
 *  read draft            no           no               yes          yes
 *  edit post             no           no               yes          yes
 *  delete post           no           no               yes          yes
 *  comment               no           yes              yes          yes
 *  edit comment          no           no               author only  author only
 *  delete comment        no           author only      author/post owner  yes
 */
const isAdmin = (u) => !!u && u.role === 'admin';

const canViewPost = (u, post) => post.published === 1 || (!!u && (u.id === post.author_id || isAdmin(u)));
const canEditPost = (u, post) => !!u && (u.id === post.author_id || isAdmin(u));
const canDeletePost = canEditPost;
const canCommentOn = (u, post) => !!u && post.published === 1;
const canEditComment = (u, c) => !!u && u.id === c.author_id;
const canDeleteComment = (u, c, post) => !!u && (u.id === c.author_id || u.id === post.author_id || isAdmin(u));

module.exports = { isAdmin, canViewPost, canEditPost, canDeletePost, canCommentOn, canEditComment, canDeleteComment };
