(function(){const t=document.createElement("link").relList;if(t&&t.supports&&t.supports("modulepreload"))return;for(const o of document.querySelectorAll('link[rel="modulepreload"]'))n(o);new MutationObserver(o=>{for(const s of o)if(s.type==="childList")for(const a of s.addedNodes)a.tagName==="LINK"&&a.rel==="modulepreload"&&n(a)}).observe(document,{childList:!0,subtree:!0});function l(o){const s={};return o.integrity&&(s.integrity=o.integrity),o.referrerpolicy&&(s.referrerPolicy=o.referrerpolicy),o.crossorigin==="use-credentials"?s.credentials="include":o.crossorigin==="anonymous"?s.credentials="omit":s.credentials="same-origin",s}function n(o){if(o.ep)return;o.ep=!0;const s=l(o);fetch(o.href,s)}})();function z(){}function le(e){return e()}function Z(){return Object.create(null)}function R(e){e.forEach(le)}function se(e){return typeof e=="function"}function oe(e,t){return e!=e?t==t:e!==t||e&&typeof e=="object"||typeof e=="function"}function re(e){return Object.keys(e).length===0}function c(e,t){e.appendChild(t)}function y(e,t,l){e.insertBefore(t,l||null)}function b(e){e.parentNode.removeChild(e)}function _(e){return document.createElement(e)}function N(e){return document.createTextNode(e)}function k(){return N(" ")}function A(e,t,l,n){return e.addEventListener(t,l,n),()=>e.removeEventListener(t,l,n)}function u(e,t,l){l==null?e.removeAttribute(t):e.getAttribute(t)!==l&&e.setAttribute(t,l)}function ue(e){return Array.from(e.childNodes)}function H(e,t){t=""+t,e.wholeText!==t&&(e.data=t)}function T(e,t){e.value=t==null?"":t}let Y;function F(e){Y=e}const q=[],$=[],W=[],ee=[],ie=Promise.resolve();let Q=!1;function ae(){Q||(Q=!0,ie.then(ne))}function X(e){W.push(e)}const G=new Set;let V=0;function ne(){const e=Y;do{for(;V<q.length;){const t=q[V];V++,F(t),ce(t.$$)}for(F(null),q.length=0,V=0;$.length;)$.pop()();for(let t=0;t<W.length;t+=1){const l=W[t];G.has(l)||(G.add(l),l())}W.length=0}while(q.length);for(;ee.length;)ee.pop()();Q=!1,G.clear(),F(e)}function ce(e){if(e.fragment!==null){e.update(),R(e.before_update);const t=e.dirty;e.dirty=[-1],e.fragment&&e.fragment.p(e.ctx,t),e.after_update.forEach(X)}}const fe=new Set;function de(e,t){e&&e.i&&(fe.delete(e),e.i(t))}function pe(e,t,l,n){const{fragment:o,on_mount:s,on_destroy:a,after_update:r}=e.$$;o&&o.m(t,l),n||X(()=>{const p=s.map(le).filter(se);a?a.push(...p):R(p),e.$$.on_mount=[]}),r.forEach(X)}function _e(e,t){const l=e.$$;l.fragment!==null&&(R(l.on_destroy),l.fragment&&l.fragment.d(t),l.on_destroy=l.fragment=null,l.ctx=[])}function he(e,t){e.$$.dirty[0]===-1&&(q.push(e),ae(),e.$$.dirty.fill(0)),e.$$.dirty[t/31|0]|=1<<t%31}function me(e,t,l,n,o,s,a,r=[-1]){const p=Y;F(e);const d=e.$$={fragment:null,ctx:null,props:s,update:z,not_equal:o,bound:Z(),on_mount:[],on_destroy:[],on_disconnect:[],before_update:[],after_update:[],context:new Map(t.context||(p?p.$$.context:[])),callbacks:Z(),dirty:r,skip_bound:!1,root:t.target||p.$$.root};a&&a(d.root);let C=!1;if(d.ctx=l?l(e,t.props||{},(x,D,...P)=>{const S=P.length?P[0]:D;return d.ctx&&o(d.ctx[x],d.ctx[x]=S)&&(!d.skip_bound&&d.bound[x]&&d.bound[x](S),C&&he(e,x)),D}):[],d.update(),C=!0,R(d.before_update),d.fragment=n?n(d.ctx):!1,t.target){if(t.hydrate){const x=ue(t.target);d.fragment&&d.fragment.l(x),x.forEach(b)}else d.fragment&&d.fragment.c();t.intro&&de(e.$$.fragment),pe(e,t.target,t.anchor,t.customElement),ne()}F(p)}class we{$destroy(){_e(this,1),this.$destroy=z}$on(t,l){const n=this.$$.callbacks[t]||(this.$$.callbacks[t]=[]);return n.push(l),()=>{const o=n.indexOf(l);o!==-1&&n.splice(o,1)}}$set(t){this.$$set&&!re(t)&&(this.$$.skip_bound=!0,this.$$set(t),this.$$.skip_bound=!1)}}function be(e){let t,l,n,o,s,a,r=e[8].message+"",p,d,C,x,D,P;function S(E,h){return h&128&&(o=null),o==null&&(o=!!E[7].status.toString().startsWith("2")),o?Ee:xe}let m=S(e,-1),L=m(e),f=e[8].address&&te(e);return{c(){t=_("h1"),t.textContent="\u{1F441}\uFE0FView server respond",l=k(),n=_("div"),L.c(),s=k(),a=_("h3"),p=N(r),d=k(),f&&f.c(),C=k(),x=_("button"),x.textContent="HOME",u(t,"class","row-start-2 col-span-6 text-xl text-center"),u(a,"class","text-2xl"),u(x,"class","bg-bitcoin w-3/4 h-3/4 rounded-2xl"),u(n,"class","col-start-1 col-span-6 lg:col-start-3 lg:col-span-2 row-span-8 row-start-3 grid grid-cols-1 grid-rows-6 items-center justify-items-center w-full h-full p-4 bg-gray-800 rounded-2xl shadow-xl")},m(E,h){y(E,t,h),y(E,l,h),y(E,n,h),L.m(n,null),c(n,s),c(n,a),c(a,p),c(n,d),f&&f.m(n,null),c(n,C),c(n,x),D||(P=A(x,"click",e[28]),D=!0)},p(E,h){m===(m=S(E,h))&&L?L.p(E,h):(L.d(1),L=m(E),L&&(L.c(),L.m(n,s))),h&256&&r!==(r=E[8].message+"")&&H(p,r),E[8].address?f?f.p(E,h):(f=te(E),f.c(),f.m(n,C)):f&&(f.d(1),f=null)},d(E){E&&b(t),E&&b(l),E&&b(n),L.d(),f&&f.d(),D=!1,P()}}}function ge(e){let t,l,n,o,s,a,r,p,d=(e[0]?e[0]:"your_name")+"",C,x,D=location.hostname+"",P,S,m,L,f,E,h,M,v,I,j;return{c(){t=_("h1"),t.textContent="\u274C\uFE0FDelete Lightning address",l=k(),n=_("button"),n.textContent="CREATE",o=k(),s=_("button"),s.textContent="EDIT",a=k(),r=_("div"),p=_("h3"),C=N(d),x=N("@"),P=N(D),S=k(),m=_("input"),L=k(),f=_("input"),E=k(),h=_("label"),h.innerHTML=`<input id="confirm" type="checkbox" class="rounded-2xl"/> 
                <span class="text-sm">I understood that address can&#39;t be restored. I want to delete it.</span>`,M=k(),v=_("button"),v.textContent="DELETE",u(t,"class","row-start-2 col-span-6 text-xl text-center"),u(n,"class","col-start-2 col-span-2 lg:col-span-1 lg:col-start-5 bg-bitcoin w-3/4 h-3/4 rounded-2xl shadow-xl"),u(s,"class","col-start-4 col-span-2 lg:col-span-1 lg:col-start-6 bg-gray-600 w-3/4 h-3/4 rounded-2xl shadow-xl"),u(p,"class","text-2xl text-center"),u(m,"maxlength","20"),u(m,"class","w-3/4 h-3/4 rounded-2xl"),u(m,"placeholder","alias"),u(f,"maxlength","128"),u(f,"type","password"),u(f,"class","w-3/4 h-3/4 rounded-2xl"),u(f,"placeholder","password"),u(h,"class","row-span-2 w-3/4"),u(v,"class","bg-red-700 w-3/4 h-3/4 rounded-2xl"),u(r,"class","col-start-1 col-span-6 lg:col-start-3 lg:col-span-2 row-span-8 row-start-3 grid grid-cols-1 grid-rows-6 items-center justify-items-center w-full h-full p-4 bg-gray-800 rounded-2xl shadow-xl")},m(i,g){y(i,t,g),y(i,l,g),y(i,n,g),y(i,o,g),y(i,s,g),y(i,a,g),y(i,r,g),c(r,p),c(p,C),c(p,x),c(p,P),c(r,S),c(r,m),T(m,e[0]),c(r,L),c(r,f),T(f,e[2]),c(r,E),c(r,h),c(r,M),c(r,v),I||(j=[A(n,"click",e[24]),A(s,"click",e[25]),A(m,"input",e[26]),A(f,"input",e[27]),A(v,"click",e[11])],I=!0)},p(i,g){g&1&&d!==(d=(i[0]?i[0]:"your_name")+"")&&H(C,d),g&1&&m.value!==i[0]&&T(m,i[0]),g&4&&f.value!==i[2]&&T(f,i[2])},d(i){i&&b(t),i&&b(l),i&&b(n),i&&b(o),i&&b(s),i&&b(a),i&&b(r),I=!1,R(j)}}}function ye(e){let t,l,n,o,s,a,r,p,d=(e[0]?e[0]:"your_name")+"",C,x,D=location.hostname+"",P,S,m,L,f,E,h,M,v,I,j,i,g,J,B,U,K;return{c(){t=_("h1"),t.textContent="\u{1F58B}Edit Lightning address",l=k(),n=_("button"),n.textContent="DELETE",o=k(),s=_("button"),s.textContent="CREATE",a=k(),r=_("div"),p=_("h3"),C=N(d),x=N("@"),P=N(D),S=k(),m=_("input"),L=k(),f=_("input"),E=k(),h=_("input"),M=k(),v=_("input"),I=k(),j=_("input"),i=k(),g=_("button"),g.textContent="UPDATE",J=k(),B=_("p"),B.textContent="*leave blank what you don't want to change",u(t,"class","row-start-2 col-span-6 text-xl text-center"),u(n,"class","col-start-2 col-span-2 lg:col-span-1 lg:col-start-5 bg-red-700 w-3/4 h-3/4 rounded-2xl shadow-xl"),u(s,"class","col-start-4 col-span-2 lg:col-span-1 lg:col-start-6 bg-bitcoin w-3/4 h-3/4 rounded-2xl shadow-xl"),u(p,"class","text-2xl w-11/12 text-center"),u(m,"maxlength","20"),u(m,"class","w-3/4 h-3/4 rounded-2xl"),u(m,"placeholder","old alias"),u(f,"maxlength","128"),u(f,"type","password"),u(f,"class","w-3/4 h-3/4 rounded-2xl"),u(f,"placeholder","old password"),u(h,"maxlength","20"),u(h,"class","w-3/4 h-3/4 rounded-2xl"),u(h,"placeholder","new alias"),u(v,"maxlength","400"),u(v,"class","w-3/4 h-3/4 rounded-2xl"),u(v,"placeholder","new lnurl"),u(j,"maxlength","128"),u(j,"type","password"),u(j,"class","w-3/4 h-3/4 rounded-2xl"),u(j,"placeholder","new password"),u(g,"class","bg-gray-600 w-3/4 h-3/4 rounded-2xl"),u(r,"class","col-start-1 col-span-6 lg:col-start-3 lg:col-span-2 row-span-8 row-start-3 grid grid-cols-1 grid-rows-7 items-center justify-items-center w-full h-full p-4 bg-gray-800 rounded-2xl shadow-xl"),u(B,"class","row-start-12 col-span-6 text-xs")},m(w,O){y(w,t,O),y(w,l,O),y(w,n,O),y(w,o,O),y(w,s,O),y(w,a,O),y(w,r,O),c(r,p),c(p,C),c(p,x),c(p,P),c(r,S),c(r,m),T(m,e[0]),c(r,L),c(r,f),T(f,e[2]),c(r,E),c(r,h),T(h,e[3]),c(r,M),c(r,v),T(v,e[4]),c(r,I),c(r,j),T(j,e[5]),c(r,i),c(r,g),y(w,J,O),y(w,B,O),U||(K=[A(n,"click",e[17]),A(s,"click",e[18]),A(m,"input",e[19]),A(f,"input",e[20]),A(h,"input",e[21]),A(v,"input",e[22]),A(j,"input",e[23]),A(g,"click",e[10])],U=!0)},p(w,O){O&1&&d!==(d=(w[0]?w[0]:"your_name")+"")&&H(C,d),O&1&&m.value!==w[0]&&T(m,w[0]),O&4&&f.value!==w[2]&&T(f,w[2]),O&8&&h.value!==w[3]&&T(h,w[3]),O&16&&v.value!==w[4]&&T(v,w[4]),O&32&&j.value!==w[5]&&T(j,w[5])},d(w){w&&b(t),w&&b(l),w&&b(n),w&&b(o),w&&b(s),w&&b(a),w&&b(r),w&&b(J),w&&b(B),U=!1,R(K)}}}function ke(e){let t,l,n,o,s,a,r,p,d=(e[0]?e[0]:"your_name")+"",C,x,D=location.hostname+"",P,S,m,L,f,E,h,M,v,I,j;return{c(){t=_("h1"),t.textContent="\u26A1\uFE0FCreate Lightning address",l=k(),n=_("button"),n.textContent="DELETE",o=k(),s=_("button"),s.textContent="EDIT",a=k(),r=_("div"),p=_("h3"),C=N(d),x=N("@"),P=N(D),S=k(),m=_("input"),L=k(),f=_("input"),E=k(),h=_("input"),M=k(),v=_("button"),v.textContent="CREATE",u(t,"class","row-start-2 col-span-6 text-xl text-center"),u(n,"class","col-start-2 col-span-2 lg:col-span-1 lg:col-start-5 bg-red-700 w-3/4 h-3/4 rounded-2xl shadow-xl"),u(s,"class","col-start-4 col-span-2 lg:col-span-1 lg:col-start-6 bg-gray-600 w-3/4 h-3/4 rounded-2xl shadow-xl"),u(p,"class","text-2xl w-11/12 text-center"),u(m,"maxlength","20"),u(m,"class","w-3/4 h-3/4 rounded-2xl"),u(m,"placeholder","alias"),u(f,"maxlength","400"),u(f,"class","w-3/4 h-3/4 rounded-2xl"),u(f,"placeholder","lnurlp"),u(h,"maxlength","128"),u(h,"type","password"),u(h,"class","w-3/4 h-3/4 rounded-2xl"),u(h,"placeholder","password"),u(v,"class","bg-bitcoin w-3/4 h-3/4 rounded-2xl"),u(r,"class","col-start-1 col-span-6 lg:col-start-3 lg:col-span-2 row-span-8 row-start-3 grid grid-cols-1 grid-rows-5 items-center justify-items-center w-full h-full p-4 bg-gray-800 rounded-2xl shadow-xl")},m(i,g){y(i,t,g),y(i,l,g),y(i,n,g),y(i,o,g),y(i,s,g),y(i,a,g),y(i,r,g),c(r,p),c(p,C),c(p,x),c(p,P),c(r,S),c(r,m),T(m,e[0]),c(r,L),c(r,f),T(f,e[1]),c(r,E),c(r,h),T(h,e[2]),c(r,M),c(r,v),I||(j=[A(n,"click",e[12]),A(s,"click",e[13]),A(m,"input",e[14]),A(f,"input",e[15]),A(h,"input",e[16]),A(v,"click",e[9])],I=!0)},p(i,g){g&1&&d!==(d=(i[0]?i[0]:"your_name")+"")&&H(C,d),g&1&&m.value!==i[0]&&T(m,i[0]),g&2&&f.value!==i[1]&&T(f,i[1]),g&4&&h.value!==i[2]&&T(h,i[2])},d(i){i&&b(t),i&&b(l),i&&b(n),i&&b(o),i&&b(s),i&&b(a),i&&b(r),I=!1,R(j)}}}function xe(e){let t,l=e[7].status+"",n;return{c(){t=_("h3"),n=N(l),u(t,"class","text-2xl text-red-700")},m(o,s){y(o,t,s),c(t,n)},p(o,s){s&128&&l!==(l=o[7].status+"")&&H(n,l)},d(o){o&&b(t)}}}function Ee(e){let t,l=e[7].status+"",n;return{c(){t=_("h3"),n=N(l),u(t,"class","text-2xl text-green-700")},m(o,s){y(o,t,s),c(t,n)},p(o,s){s&128&&l!==(l=o[7].status+"")&&H(n,l)},d(o){o&&b(t)}}}function te(e){let t,l,n,o=e[8].address+"",s;return{c(){t=_("h3"),t.textContent="\u{1F389}",l=k(),n=_("h3"),s=N(o),u(t,"class","text-4xl"),u(n,"class","text-2xl")},m(a,r){y(a,t,r),y(a,l,r),y(a,n,r),c(n,s)},p(a,r){r&256&&o!==(o=a[8].address+"")&&H(s,o)},d(a){a&&b(t),a&&b(l),a&&b(n)}}}function Ce(e){let t;function l(s,a){if(s[6]==="create")return ke;if(s[6]==="edit")return ye;if(s[6]==="delete")return ge;if(s[6]==="message")return be}let n=l(e),o=n&&n(e);return{c(){t=_("main"),o&&o.c(),u(t,"class","grid grid-rows-12 grid-cols-6 p-2 items-center justify-items-center bg-base font-mono")},m(s,a){y(s,t,a),o&&o.m(t,null)},p(s,[a]){n===(n=l(s))&&o?o.p(s,a):(o&&o.d(1),o=n&&n(s),o&&(o.c(),o.m(t,null)))},i:z,o:z,d(s){s&&b(t),o&&o.d()}}}function ve(e,t,l){let n,o,s,a,r,p,d="create",C={},x={};const D=async()=>{n&&o&&s?(l(7,C=await fetch("/new",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({alias:n.trim(),lnurl:o.trim(),secret:s})})),l(8,x=await C.json()),l(6,d="message")):alert("Please fill all fields")},P=async()=>{n&&s?(l(7,C=await fetch(`/update/${n}/${s}`,{method:"PUT",headers:{"Content-Type":"application/json"},body:JSON.stringify({newAlias:a?a.trim():n.trim(),newLnurl:r?r.trim():null,newSecret:p||s})})),l(8,x=await C.json()),l(6,d="message"),l(1,o=r?r.trim():o.trim()),l(0,n=a?a.trim():n.trim()),l(2,s=p||s)):alert("Please fill in all fields")},S=async()=>{document.getElementById("confirm").checked&&n&&s?(l(7,C=await fetch(`/delete/${n}/${s}`,{method:"DELETE"})),l(8,x=await C.json()),l(6,d="message")):alert("Please fill all fields to confirm the deletion")},m=()=>{l(6,d="delete")},L=()=>{l(6,d="edit")};function f(){n=this.value,l(0,n)}function E(){o=this.value,l(1,o)}function h(){s=this.value,l(2,s)}const M=()=>{l(6,d="delete")},v=()=>{l(6,d="create")};function I(){n=this.value,l(0,n)}function j(){s=this.value,l(2,s)}function i(){a=this.value,l(3,a)}function g(){r=this.value,l(4,r)}function J(){p=this.value,l(5,p)}const B=()=>{l(6,d="create")},U=()=>{l(6,d="edit")};function K(){n=this.value,l(0,n)}function w(){s=this.value,l(2,s)}return[n,o,s,a,r,p,d,C,x,D,P,S,m,L,f,E,h,M,v,I,j,i,g,J,B,U,K,w,()=>{l(6,d="create")}]}class Le extends we{constructor(t){super(),me(this,t,ve,Ce,oe,{})}}new Le({target:document.getElementById("app")});
