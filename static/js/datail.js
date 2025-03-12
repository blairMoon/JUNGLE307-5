$(document).ready(function () {
  const postId = $(".detail-page").data("post-id");
  const accessToken = localStorage.getItem("accessToken");

  axios
    .get(`${baseURL}api/posts/${postId}`, {
      headers: {
        Authorization: `Bearer ${accessToken}`,
      },
    })
    .then((res) => {
      const post = res.data;
      renderPost(post);
      renderComments(post.comments);
    })
    .catch((err) => {
      console.error("❌ 게시글 API 호출 실패:", err);
      alert("게시글 정보를 불러오는 데 실패했어요 🥲");
    });

  function renderPost(post) {
    $(".title").text(post.title);
    $(".category").text(post.category);
    $(".status").text(post.staus ? "진행중" : "완료");
    $(".price").text(post.price ? post.price + "원" : "무료나눔");
    $(".description").text(post.description);
    $(".author").text(post.nick_name);
    $(".date").text(post.created_at);

    if (post.image_url) {
      $(".image-box img").attr("src", post.image_url);
    }

    if (post.isAuthor) {
      $(".actions").show(); // 수정/삭제 버튼 보이기
    }
  }

  function renderComments(comments) {
    const list = $(".comment-list");
    list.empty();

    comments.forEach((comment) => {
      const repliesHTML = comment.replies
        .map((reply) => {
          return `
              <li class="reply">
                <span class="nickname">${
                  reply.isAuthor ? "<strong>작성자</strong>" : reply.writer
                }</span>
                <p class="reply-content">${reply.content}</p>
                <span class="date">${reply.created_at}</span>
              </li>
            `;
        })
        .join("");

      const commentHTML = `
          <li class="comment">
            <div class="comment-wrp">
              <div class="comment-header">
                <span class="nickname"><strong>${comment.writer}</strong></span>
                <span class="date">${comment.created_at}</span>
              </div>
              <p class="comment-content">${comment.content}</p>
            </div>
            <button class="toggle-reply">답글</button>
            <form class="reply-form hidden">
              <input type="text" placeholder="답글 입력" />
              <button type="submit">답글</button>
            </form>
            <ul class="replies">${repliesHTML}</ul>
          </li>
        `;

      list.append(commentHTML);
    });

    $(".toggle-reply").on("click", function () {
      $(this).next(".reply-form").toggleClass("hidden");
    });
  }
});
