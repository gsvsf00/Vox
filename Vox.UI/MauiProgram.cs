using Microsoft.Extensions.Logging;
using Vox.Services;

namespace Vox
{
    public static class MauiProgram
    {
        public static MauiApp CreateMauiApp()
        {
            var builder = MauiApp.CreateBuilder();
            builder
                .UseMauiApp<App>()
                .ConfigureFonts(fonts =>
                {
                    fonts.AddFont("OpenSans-Regular.ttf", "OpenSansRegular");
                    fonts.AddFont("OpenSans-Semibold.ttf", "OpenSansSemibold");
                });

            builder.Services.AddMauiBlazorWebView();

#if DEBUG
            builder.Services.AddBlazorWebViewDeveloperTools();
    		builder.Logging.AddDebug();
#endif

            // Phase 5 MVP: in-memory stubs for services not yet wired to transport
            StubServices.Register(builder.Services);

            // Application Facade — singleton so all UI components share state
            builder.Services.AddSingleton<AppState>();

            return builder.Build();
        }
    }
}
