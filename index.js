$(document).ready(function () {
  $(".fa-search").click(function () {
    $(".search-box").toggle();
    $("input[type='text']").focus();
  });
});
